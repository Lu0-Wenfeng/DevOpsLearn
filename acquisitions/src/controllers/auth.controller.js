import logger from '#config/logger.js';
import { createUser } from '#services/auth.service.js';
import { formatValidationError } from '#utils/format.js';
import { jwtToken } from '#utils/jwt.js';
import { signupSchema } from '../validations/auth.validation.js';
import { cookies } from '#utils/cookies.js';

export const signup = async (req, res, next) => {
  try {
    const validationResult = signupSchema.safeParse(req.body);
    if (!validationResult.success) {
      return res.status(400).json({
        message: 'Validation error',
        details: formatValidationError(validationResult.error),
      });
    }

    const { name, email, role, password } = validationResult.data;

    const user = await createUser({ name, email, password, role });

    const token = jwtToken.sign({
      id: user.id,
      email: user.email,
      role: user.role,
    });

    cookies.set(res, 'token', token);

    logger.info('User registered', { name, email, role });
    res.status(201).json({
      message: 'User registered',
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    });
  } catch (error) {
    logger.error('Error during sign-up', error);

    if (error.message === 'User with this email already exists') {
      return res.status(409).json({ message: 'Email already exist' });
    }

    next(error);
  }
};
