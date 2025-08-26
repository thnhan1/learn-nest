import {
    Body,
    Controller,
    Get,
    HttpCode,
    HttpStatus,
    Post,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { Public } from 'src/decorator/public.decorator';
import { User } from 'src/decorator/user.decorator';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';

@Controller('auth')
export class AuthController {
    constructor(private authService: AuthService) {}

    @Public()
    @Post('register')
    register(@Body() dto: RegisterDto) {
        return this.authService.register(dto.email, dto.password, dto.role);
    }

    @HttpCode(HttpStatus.OK)
    @Public()
    @Post('login')
    signIn(@Body() dto: LoginDto) {
        return this.authService.signIn(dto.email, dto.password);
    }

    @Get('profile')
    getProfile(@User() user: any) {
        return user;
    }
}
