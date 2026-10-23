const { z } = require('zod');

const registerSchema = z.object({
  name: z.string().min(2).max(100).trim(),
  email: z.string().email().toLowerCase().trim(),
  password: z.string().min(8).max(128).regex(
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/,
    'Password must contain at least one uppercase letter, one lowercase letter, and one number'
  ),
});

const loginSchema = z.object({
  email: z.string().email().toLowerCase().trim(),
  password: z.string().min(1).max(128),
});

const analyzeUrlSchema = z.object({
  url: z.string().min(1).max(2048).trim(),
  scanType: z.enum(['qr_upload', 'qr_camera', 'url_direct', 'file_link', 'extension']).default('url_direct'),
  trustedQrId: z.string().optional(),
  inspectRedirects: z.boolean().default(true),
});

const registerQrSchema = z.object({
  expectedDestination: z.string().url().max(2048),
  label: z.string().min(1).max(200).trim(),
  description: z.string().max(1000).trim().optional(),
});

const createOrgSchema = z.object({
  name: z.string().min(2).max(200).trim(),
  verifiedDomain: z.string().optional(),
  contactEmail: z.string().email().optional(),
});

const updatePasswordSchema = z.object({
  currentPassword: z.string().min(1),
  newPassword: z.string().min(8).max(128).regex(
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/,
    'Password must contain at least one uppercase letter, one lowercase letter, and one number'
  ),
});

const paginationSchema = z.object({
  page: z.coerce.number().int().positive().default(1),
  limit: z.coerce.number().int().positive().max(100).default(20),
});

/**
 * Middleware factory for Zod validation.
 */
function validate(schema, target = 'body') {
  return (req, res, next) => {
    const result = schema.safeParse(req[target]);
    if (!result.success) {
      return res.status(400).json({
        success: false,
        error: 'Validation failed',
        code: 'VALIDATION_ERROR',
        details: result.error.errors.map(e => ({
          field: e.path.join('.'),
          message: e.message,
        })),
      });
    }
    req[target] = result.data;
    next();
  };
}

module.exports = {
  validate,
  registerSchema,
  loginSchema,
  analyzeUrlSchema,
  registerQrSchema,
  createOrgSchema,
  updatePasswordSchema,
  paginationSchema,
};
