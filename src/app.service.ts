import { Injectable } from '@nestjs/common';

@Injectable()
export class AppService {
    getHello(): string {
        return 'Hello World!';
    }

    getAdminInfo() {
        return {
            name: 'Tran Nhan',
            age: 22,
            role: 'admin'
        }
    }

}
