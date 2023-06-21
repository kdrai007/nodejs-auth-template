import { check, validationResult } from 'express-validator';

export const validateUser = [
  check('name')
    .trim()
    .not()
    .isEmpty()
    .withMessage('Name is missing')
    .isLength({ min: 3, max: 30 })
    .withMessage('Name must be 3 to 30 characters long!'),
  check('email').normalizeEmail().isEmail().withMessage('Email is invalid'),
  check('password')
    .trim()
    .not()
    .isEmpty()
    .withMessage('password is missing')
    .isLength({ min: 5 })
    .withMessage('Password is short'),
];

export const validate = (req, res, next) => {
  const error = validationResult(req).array();
  if (error.length > 0)
    return res.status(400).json({ success: false, error: error[0].msg });
  next();
};
