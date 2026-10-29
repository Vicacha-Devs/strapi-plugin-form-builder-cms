import {
  formatFileCellForCsv,
  isUploadedFileList,
  RawUploadedFile,
  SanitizedFileForStrapi,
  UploadedFileItem,
  validateUploadedFilesForField,
} from '../lib/file-upload';

const PLUGIN_ID = 'strapi-plugin-form-builder-cms';
const SUBMISSION_UID = `plugin::${PLUGIN_ID}.form-submission`;
const FORM_UID = `plugin::${PLUGIN_ID}.form`;

const CAPTCHA_ENDPOINTS: Record<string, string> = {
  turnstile: 'https://challenges.cloudflare.com/turnstile/v0/siteverify',
  recaptcha: 'https://www.google.com/recaptcha/api/siteverify',
};

// Server-side token check. Fails closed: any network/parse error rejects the submission.
export async function verifyCaptcha(provider: string, secret: string, token: string, ip: string): Promise<boolean> {
  const url = CAPTCHA_ENDPOINTS[provider];
  if (!url) return false; // unknown provider — fail closed
  // trim: users often paste keys with stray leading/trailing whitespace
  const params = new URLSearchParams({ secret: (secret || '').trim(), response: (token || '').trim() });
  if (ip) params.append('remoteip', ip);
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: params.toString(),
      signal: AbortSignal.timeout(5000), // don't hang the submit if the provider stalls
    });
    const json: any = await res.json();
    return !!json.success;
  } catch {
    return false;
  }
}

export default ({ strapi }: { strapi: any }) => ({
  // Validate a CAPTCHA secret key against the provider (called from the admin settings
  // "Test" button). A dummy token is sent: a valid secret comes back with an
  // "invalid-input-response" error (secret OK, token bad); an invalid secret returns
  // "invalid-input-secret". This lets us catch wrong secret keys before publishing.
  async testCaptchaSecret(provider: string, secret: string): Promise<{ ok: boolean; reason?: string }> {
    const url = CAPTCHA_ENDPOINTS[provider];
    if (!url) return { ok: false, reason: 'Unknown provider' };
    if (!secret || !secret.trim()) return { ok: false, reason: 'Secret key is empty' };
    const params = new URLSearchParams({ secret: secret.trim(), response: 'test-token' });
    try {
      const res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: params.toString(),
        signal: AbortSignal.timeout(5000),
      });
      const json: any = await res.json();
      const codes: string[] = json['error-codes'] || [];
      if (codes.includes('invalid-input-secret') || codes.includes('missing-input-secret')) {
        return { ok: false, reason: 'Secret key is invalid' };
      }
      return { ok: true };
    } catch {
      return { ok: false, reason: 'Could not reach the CAPTCHA provider' };
    }
  },

  async submit(
    slug: string,
    body: Record<string, any>,
    meta: { ip: string; userAgent: string },
    filesByField: Record<string, RawUploadedFile[]> = {}
  ) {
    const form = await strapi
      .plugin(PLUGIN_ID)
      .service('form')
      .findBySlug(slug);

    // Only a published form accepts submissions, and against its published
    // snapshot — not the working draft the admin may be editing.
    if (!form || !form.publishedAt) {
      const err: any = new Error('Form not found');
      err.name = 'NotFoundError';
      throw err;
    }
    // Legacy fallback: forms published before publishedData existed use their current copy.
    const pd = form.publishedData || { fields: form.fields, settings: form.settings };
    const live = { fields: pd.fields || [], settings: pd.settings || {} };

    const allFields: any[] = live.fields || [];
    const fileFields = allFields.filter((f: any) => f.type === 'file');
    const nonFileFields = allFields.filter((f: any) => f.type !== 'file');

    // Prevent JSON body spoofing of file fields: file values can only originate from validated multipart uploads
    const sanitizedBody: Record<string, any> = { ...(body || {}) };
    for (const ff of fileFields) {
      delete sanitizedBody[ff.name];
    }

    const validationService = strapi.plugin(PLUGIN_ID).service('validation');
    const result = validationService.validate(nonFileFields, sanitizedBody);

    const sanitizedFilesByField: Record<string, SanitizedFileForStrapi[]> = {};
    for (const ff of fileFields) {
      const fileResult = validateUploadedFilesForField(ff, filesByField?.[ff.name]);
      if (!fileResult.valid) {
        result.valid = false;
        result.errors[ff.name] = fileResult.errors;
      } else {
        sanitizedFilesByField[ff.name] = fileResult.sanitizedFiles;
      }
    }

    if (!result.valid) {
      const err: any = new Error('Validation failed');
      err.name = 'ValidationError';
      err.details = result.errors;
      throw err;
    }

    // Honeypot check — bot filled the hidden trap field, pretend success and drop it
    if (live.settings?.enableHoneypot && sanitizedBody._fc_hp) {
      return { success: true, successMessage: live.settings?.successMessage };
    }

    // CAPTCHA — verify the challenge token against the provider before accepting
    const captcha = live.settings?.captcha;
    if (captcha && captcha.provider && captcha.provider !== 'none' && captcha.secretKey) {
      const ok = await verifyCaptcha(captcha.provider, captcha.secretKey, sanitizedBody._fc_captcha, meta.ip);
      if (!ok) {
        const err: any = new Error('Captcha verification failed. Please try again.');
        err.name = 'CaptchaError';
        throw err;
      }
    }

    // Rate limit per form + IP over the last hour
    if (live.settings?.enableRateLimit && meta.ip) {
      const max = Number(live.settings?.maxSubmissionsPerHour) || 60;
      const since = new Date(Date.now() - 60 * 60 * 1000);
      // ponytail: naive per-request count, fine at this scale; move to a store if throughput matters
      const recent = await strapi.db.query(SUBMISSION_UID).count({
        where: { form: form.id, ipAddress: meta.ip, createdAt: { $gt: since } },
      });
      if (recent >= max) {
        const err: any = new Error('Too many submissions, please try again later');
        err.name = 'RateLimitError';
        throw err;
      }
    }

    // strip honeypot + captcha token before persisting so they never land in stored data
    const { _fc_hp, _fc_captcha, ...clean } = sanitizedBody;

    // Freeze the field schema used at submit time so the record stays accurate
    // even if the form's fields are later added, removed or renamed.
    const decorative = ['heading', 'paragraph', 'divider'];
    const fieldsSnapshot = allFields
      .filter((f: any) => !decorative.includes(f.type))
      .map((f: any) => ({
        name: f.name,
        label: f.label,
        type: f.type,
        order: f.order,
        options: f.options,
        ...(f.type === 'file'
          ? {
              accept: f.accept,
              maxSizeMb: f.maxSizeMb,
              multiple: f.multiple,
              maxFiles: f.maxFiles,
            }
          : {}),
      }));

    const uploadedMediaRecords: any[] = [];
    const uploadPlugin = strapi.plugin?.('upload');
    const uploadService = uploadPlugin?.service?.('upload');
    const folderService = uploadPlugin?.service?.('api-upload-folder');

    try {
      if (fileFields.length > 0) {
        let folderId: number | null = null;
        if (folderService?.getAPIUploadFolder) {
          try {
            const folder = await folderService.getAPIUploadFolder();
            folderId = folder?.id ?? null;
          } catch {
            folderId = null;
          }
        }

        for (const ff of fileFields) {
          const sanitizedList = sanitizedFilesByField[ff.name] || [];
          if (sanitizedList.length === 0) {
            clean[ff.name] = [];
            continue;
          }
          if (!uploadService?.upload) {
            throw new Error('Strapi upload service is not available');
          }

          const uploadedItems: UploadedFileItem[] = [];
          for (const sf of sanitizedList) {
            const uploaded = await uploadService.upload({
              data: {
                fileInfo: {
                  name: sf.displayName,
                  caption: `${form.slug} - ${ff.label || ff.name}`,
                  alternativeText: sf.displayName,
                  ...(folderId ? { folder: folderId } : {}),
                },
              },
              files: {
                filepath: sf.filepath,
                originalFilename: sf.originalFilename,
                mimetype: sf.mimetype,
                detectedMimeType: sf.detectedMimeType,
                size: sf.size,
              },
            });

            const rec = Array.isArray(uploaded) ? uploaded[0] : uploaded;
            if (rec) {
              uploadedMediaRecords.push(rec);
              uploadedItems.push({
                id: rec.id,
                ...(rec.documentId ? { documentId: rec.documentId } : {}),
                name: sf.displayName,
                url: String(rec.url || ''),
                mime: String(rec.mime || sf.mimetype),
                size: sf.size,
                ext: sf.ext,
              });
            }
          }
          clean[ff.name] = uploadedItems;
        }
      }

      await strapi.db.query(SUBMISSION_UID).create({
        data: {
          form: form.id,
          data: clean,
          fields: fieldsSnapshot,
          ipAddress: meta.ip,
          userAgent: meta.userAgent,
          status: 'new',
        },
      });
    } catch (createErr: any) {
      // Roll back any Media Library files uploaded during this request so no orphans remain
      if (uploadedMediaRecords.length > 0 && uploadService?.remove) {
        for (const rec of uploadedMediaRecords) {
          try {
            await uploadService.remove(rec);
          } catch {
            // best-effort rollback
          }
        }
      }
      console.error('[sfb] create error:', createErr?.message, createErr?.stack);
      throw createErr;
    }

    return { success: true, successMessage: live.settings?.successMessage };
  },

  async find(formId: number, query: any = {}) {
    const { page = 1, pageSize = 25, status } = query;
    const where: any = { form: formId };
    if (status) where.status = status;

    const [results, total] = await Promise.all([
      strapi.db.query(SUBMISSION_UID).findMany({
        where,
        populate: ['form'],
        orderBy: { createdAt: 'desc' },
        limit: Number(pageSize),
        offset: (Number(page) - 1) * Number(pageSize),
      }),
      strapi.db.query(SUBMISSION_UID).count({ where }),
    ]);

    return {
      results,
      pagination: {
        page: Number(page),
        pageSize: Number(pageSize),
        total,
        pageCount: Math.ceil(total / Number(pageSize)),
      },
    };
  },

  async findOne(id: number) {
    return strapi.db.query(SUBMISSION_UID).findOne({
      where: { id },
      populate: ['form'],
    });
  },

  async updateStatus(id: number, status: string) {
    return strapi.db.query(SUBMISSION_UID).update({
      where: { id },
      data: { status },
    });
  },

  async delete(id: number) {
    return strapi.db.query(SUBMISSION_UID).delete({ where: { id } });
  },

  async export(formId: number, format: string = 'csv') {
    const form = await strapi.db.query(FORM_UID).findOne({ where: { id: formId } });
    const submissions = await strapi.db.query(SUBMISSION_UID).findMany({
      where: { form: formId },
      orderBy: { createdAt: 'desc' },
    });

    const fields: any[] = form?.fields || [];
    const fieldNames = fields
      .filter((f: any) => !['heading', 'paragraph', 'divider'].includes(f.type))
      .map((f: any) => f.name);

    const headers = ['id', 'status', 'createdAt', ...fieldNames];
    const rows = submissions.map((s: any) => [
      s.id,
      s.status,
      s.createdAt,
      ...fieldNames.map((name: string) => {
        const val = s.data?.[name];
        return isUploadedFileList(val) ? formatFileCellForCsv(val) : (val ?? '');
      }),
    ]);

    // ponytail: CSV only. Add xlsx with a real writer (exceljs) if someone actually needs it.
    const csvCell = (v: any) => {
      let s = String(v);
      // neutralize spreadsheet formula injection (=, +, -, @ leading chars)
      if (/^[=+\-@]/.test(s)) s = `'${s}`;
      return `"${s.replace(/"/g, '""')}"`;
    };
    const lines = [
      headers.join(','),
      ...rows.map((r: any[]) => r.map(csvCell).join(',')),
    ];
    return lines.join('\n');
  },

  async getStats(formId: number) {
    const all = await strapi.db.query(SUBMISSION_UID).findMany({
      where: { form: formId },
    });
    const total = all.length;
    const byStatus: Record<string, number> = { new: 0, read: 0, archived: 0 };
    for (const s of all) {
      byStatus[s.status] = (byStatus[s.status] || 0) + 1;
    }
    return { total, byStatus };
  },
});
