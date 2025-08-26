import { Injectable, NestMiddleware } from '@nestjs/common';
import { NextFunction } from 'express';

@Injectable()
export class ClassMiddleware implements NestMiddleware {
    use(req: Request, res: Response, next: NextFunction) {
        console.log('class middleware...');
        next();
    }
}
