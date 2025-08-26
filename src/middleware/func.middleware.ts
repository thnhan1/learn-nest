import { NextFunction, Response } from 'express';

export function funcMiddleware(
    req: Request,
    res: Response,
    next: NextFunction,
) {
    console.log('function middleware...');
    next();
}
