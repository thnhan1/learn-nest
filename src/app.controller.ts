import { Controller, Get, UseGuards } from '@nestjs/common';
import { AppService } from './app.service';
import { Roles } from './decorator/roles.decorator';
import { RolesGuard } from './guard/roles.guard';
import { User } from './decorator/user.decorator';

@Controller()
export class AppController {
    constructor(private readonly appService: AppService) {}

    @Get()
    getHello(): string {
        return this.appService.getHello();
    }


    @Roles(['user'])
    @Get('admin')
    @UseGuards(RolesGuard)
    getAdminInfo() {
        return this.appService.getAdminInfo()
    }

    @Get('user')
    getUser(@User() user: any) {
        return user;
    }
}
