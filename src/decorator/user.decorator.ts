import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { Request } from 'express';

export const User = createParamDecorator(
    (_data: unknown, ctx: ExecutionContext) => {
        const request  = ctx.switchToHttp().getRequest();
        return request.user;
    },
);
