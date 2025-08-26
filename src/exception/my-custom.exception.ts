import { HttpException, HttpStatus } from '@nestjs/common';

export class MyForbiddenException extends HttpException {
    constructor() {
        super('My Forbidden exception', HttpStatus.FORBIDDEN);
    }
}
