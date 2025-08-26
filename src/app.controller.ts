import { Controller, Get, UseGuards } from '@nestjs/common';
import { AppService } from './app.service';
import { User } from './decorator/user.decorator';
import { RolesGuard } from './guard/roles.guard';

@Controller()
export class AppController {
    constructor(private readonly appService: AppService) {}

    @Get()
    getHello(): string {
        return this.appService.getHello();
    }

    @Get('admin')
    @UseGuards(RolesGuard)
    getAdminInfo() {
        return this.appService.getAdminInfo();
    }

    @Get('user')
    getUser(@User() user: any) {
        return user;
    }
}
