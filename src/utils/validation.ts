import Joi from 'joi';
export const riskSchema = Joi.object({
  email: Joi.string().optional(),
  phone: Joi.string().optional(),
  ip: Joi.string().optional(),
  country_code: Joi.string().length(2).uppercase().optional(),
}).or('email', 'phone', 'ip').messages({
  'object.missing': 'At least one of email, phone, or ip is required',
});
