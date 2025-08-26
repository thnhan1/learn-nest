# Hướng dẫn triển khai JWT Security cho NestJS REST API

## 🚀 Bước triển khai từng bước

### Bước 1: Cài đặt dependencies
```bash
npm install @nestjs/jwt @nestjs/passport bcryptjs class-validator class-transformer
npm install -D @types/bcryptjs
```

### Bước 2: Tạo cấu trúc thư mục
```bash
# Tạo các thư mục cần thiết
mkdir -p src/auth/dto
mkdir -p src/guard
mkdir -p src/decorator
mkdir -p src/users
```

### Bước 3: Thiết lập Database Schema
```prisma
// prisma/schema.prisma
enum Role {
  USER
  ADMIN
}

model User {
  id        Int      @id @default(autoincrement())
  email     String   @unique
  password  String
  role      Role     @default(USER)
  createdAt DateTime @default(now())
  updatedAt DateTime @updatedAt
}
```

### Bước 4: Tạo JWT Constants
```typescript
// src/auth/constants.ts
export const jwtConstants = {
    secret: process.env.JWT_SECRET || 'your-super-secret-key',
};
```

### Bước 5: Tạo DTOs cho Authentication
```typescript
// src/auth/dto/login.dto.ts
import { IsEmail, IsString, MinLength } from 'class-validator';

export class LoginDto {
    @IsEmail()
    email: string;

    @IsString()
    @MinLength(6)
    password: string;
}
```

```typescript
// src/auth/dto/register.dto.ts
import { Role } from '@prisma/client';
import { IsEmail, IsEnum, IsOptional, IsString, MinLength } from 'class-validator';

export class RegisterDto {
    @IsEmail()
    email: string;

    @IsString()
    @MinLength(6)
    password: string;

    @IsOptional()
    @IsEnum(Role)
    role?: Role;
}
```

### Bước 6: Tạo Users Service
```typescript
// src/users/users.service.ts
import { Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { Role } from '@prisma/client';

@Injectable()
export class UsersService {
    constructor(private readonly prisma: PrismaService) {}

    async create(data: { email: string; password: string; role?: Role }) {
        return this.prisma.user.create({ data });
    }

    async findByEmail(email: string) {
        return this.prisma.user.findUnique({ where: { email } });
    }

    async findById(id: number) {
        return this.prisma.user.findUnique({ where: { id } });
    }
}
```

### Bước 7: Tạo Auth Service
```typescript
// src/auth/auth.service.ts
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UsersService } from 'src/users/users.service';
import * as bcrypt from 'bcryptjs';
import { Role } from '@prisma/client';
import { jwtConstants } from './constants';

@Injectable()
export class AuthService {
    constructor(
        private usersService: UsersService,
        private jwtService: JwtService,
    ) {}

    async register(email: string, password: string, role: Role = Role.USER) {
        const hash = await bcrypt.hash(password, 12);
        return this.usersService.create({ email, password: hash, role });
    }

    async signIn(email: string, pass: string): Promise<{ access_token: string }> {
        const user = await this.usersService.findByEmail(email);
        if (!user || !(await bcrypt.compare(pass, user.password))) {
            throw new UnauthorizedException('Invalid credentials');
        }
        
        const payload = { 
            sub: user.id, 
            email: user.email, 
            role: user.role 
        };
        
        return {
            access_token: await this.jwtService.signAsync(payload, {
                secret: jwtConstants.secret,
            }),
        };
    }
}
```

### Bước 8: Tạo Custom Decorators
```typescript
// src/decorator/public.decorator.ts
import { SetMetadata } from '@nestjs/common';

export const IS_PUBLIC_KEY = 'isPublic';
export const Public = () => SetMetadata(IS_PUBLIC_KEY, true);
```

```typescript
// src/decorator/user.decorator.ts
import { createParamDecorator, ExecutionContext } from '@nestjs/common';

export const User = createParamDecorator(
    (_data: unknown, ctx: ExecutionContext) => {
        const request = ctx.switchToHttp().getRequest();
        return request.user;
    },
);
```

```typescript
// src/decorator/roles.decorator.ts
import { SetMetadata } from '@nestjs/common';

export const ROLES_KEY = 'roles';
export const Roles = (...roles: string[]) => SetMetadata(ROLES_KEY, roles);
```

### Bước 9: Tạo Auth Guard
```typescript
// src/guard/auth.guard.ts
import {
    CanActivate,
    ExecutionContext,
    Injectable,
    UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { JwtService } from '@nestjs/jwt';
import { Request } from 'express';
import { jwtConstants } from 'src/auth/constants';
import { IS_PUBLIC_KEY } from 'src/decorator/public.decorator';
import { UsersService } from 'src/users/users.service';

@Injectable()
export class AuthGuard implements CanActivate {
    constructor(
        private readonly jwtService: JwtService,
        private reflector: Reflector,
        private usersService: UsersService,
    ) {}

    async canActivate(context: ExecutionContext): Promise<boolean> {
        const isPublic = this.reflector.getAllAndOverride<boolean>(
            IS_PUBLIC_KEY,
            [context.getHandler(), context.getClass()],
        );

        if (isPublic) {
            return true;
        }

        const request = context.switchToHttp().getRequest();
        const token = this.extractTokenFromHeader(request);
        
        if (!token) {
            throw new UnauthorizedException('Token not found');
        }

        try {
            const payload = await this.jwtService.verifyAsync(token, {
                secret: jwtConstants.secret,
            });
            
            const user = await this.usersService.findById(payload.sub);
            if (!user) {
                throw new UnauthorizedException('User not found');
            }
            
            request['user'] = user;
        } catch (error) {
            throw new UnauthorizedException('Invalid token');
        }

        return true;
    }

    private extractTokenFromHeader(request: Request): string | undefined {
        const [type, token] = request.headers.authorization?.split(' ') ?? [];
        return type === 'Bearer' ? token : undefined;
    }
}
```

### Bước 10: Tạo Roles Guard
```typescript
// src/guard/roles.guard.ts
import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ROLES_KEY } from 'src/decorator/roles.decorator';

@Injectable()
export class RolesGuard implements CanActivate {
    constructor(private reflector: Reflector) {}

    canActivate(context: ExecutionContext): boolean {
        const requiredRoles = this.reflector.getAllAndOverride<string[]>(
            ROLES_KEY,
            [context.getHandler(), context.getClass()],
        );
        
        if (!requiredRoles) {
            return true;
        }
        
        const { user } = context.switchToHttp().getRequest();
        return requiredRoles.includes(user?.role);
    }
}
```

### Bước 11: Tạo Auth Controller
```typescript
// src/auth/auth.controller.ts
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
        return {
            id: user.id,
            email: user.email,
            role: user.role,
            createdAt: user.createdAt,
        };
    }
}
```

### Bước 12: Cấu hình Auth Module
```typescript
// src/auth/auth.module.ts
import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { UsersModule } from 'src/users/users.module';
import { JwtModule } from '@nestjs/jwt';
import { jwtConstants } from './constants';

@Module({
    imports: [
        UsersModule,
        JwtModule.register({
            global: true,
            secret: jwtConstants.secret,
            signOptions: {
                expiresIn: '1h',
            },
        }),
    ],
    controllers: [AuthController],
    providers: [AuthService],
})
export class AuthModule {}
```

### Bước 13: Cấu hình Users Module
```typescript
// src/users/users.module.ts
import { Module } from '@nestjs/common';
import { UsersService } from './users.service';
import { PrismaModule } from 'src/prisma/prisma.module';

@Module({
    imports: [PrismaModule],
    providers: [UsersService],
    exports: [UsersService],
})
export class UsersModule {}
```

### Bước 14: Cấu hình App Module với Global Guards
```typescript
// src/app.module.ts
import { Module } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { AuthGuard } from './guard/auth.guard';
import { RolesGuard } from './guard/roles.guard';
import { AuthModule } from './auth/auth.module';
import { UsersModule } from './users/users.module';
import { PrismaModule } from './prisma/prisma.module';

@Module({
    imports: [PrismaModule, AuthModule, UsersModule],
    providers: [
        {
            provide: APP_GUARD,
            useClass: AuthGuard,
        },
        {
            provide: APP_GUARD,
            useClass: RolesGuard,
        },
    ],
})
export class AppModule {}
```

### Bước 15: Cấu hình main.ts
```typescript
// src/main.ts
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';

async function bootstrap() {
    const app = await NestFactory.create(AppModule, {
        cors: {
            origin: process.env.FRONTEND_URL || 'http://localhost:3000',
            methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
            allowedHeaders: ['Content-Type', 'Authorization'],
            credentials: true,
        },
    });

    // Global validation pipe
    app.useGlobalPipes(
        new ValidationPipe({
            whitelist: true,
            forbidNonWhitelisted: true,
            transform: true,
            transformOptions: {
                enableImplicitConversion: true,
            },
        }),
    );

    await app.listen(process.env.PORT ?? 3000);
}

bootstrap();
```

## 🔐 Environment Variables
Tạo file `.env`:
```env
JWT_SECRET=your-super-secret-jwt-key-here
DATABASE_URL="postgresql://username:password@localhost:5432/nestjs_jwt_db"
FRONTEND_URL=http://localhost:3000
PORT=3000
```

## 🧪 Testing Implementation

### 1. Test Registration
```bash
curl -X POST http://localhost:3000/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@example.com",
    "password": "password123",
    "role": "ADMIN"
  }'
```

### 2. Test Login
```bash
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@example.com", 
    "password": "password123"
  }'
```

### 3. Test Protected Route
```bash
curl -X GET http://localhost:3000/auth/profile \
  -H "Authorization: Bearer YOUR_JWT_TOKEN_HERE"
```

## 📋 Checklist triển khai

- [ ] Cài đặt tất cả dependencies cần thiết
- [ ] Tạo database schema với User model
- [ ] Thiết lập JWT constants và environment variables
- [ ] Tạo DTOs với validation
- [ ] Implement Users Service cho database operations
- [ ] Implement Auth Service với bcrypt hashing
- [ ] Tạo custom decorators (@Public, @User, @Roles)
- [ ] Implement Auth Guard cho JWT verification
- [ ] Implement Roles Guard cho role-based access
- [ ] Tạo Auth Controller với endpoints
- [ ] Cấu hình modules và global guards
- [ ] Test tất cả endpoints
- [ ] Cấu hình CORS và validation pipes
- [ ] Thiết lập environment variables cho production

## ⚠️ Lưu ý bảo mật quan trọng

1. **Không bao giờ commit JWT secret vào git**
2. **Sử dụng HTTPS trong production**
3. **Thiết lập token expiration phù hợp**
4. **Implement refresh token cho session dài hạn**
5. **Sử dụng bcrypt với salt rounds >= 12 cho production**
6. **Validate và sanitize tất cả input data**
7. **Implement rate limiting cho auth endpoints**
8. **Log các hoạt động authentication cho monitoring**

---

Hướng dẫn này cung cấp một implementation hoàn chỉnh và bảo mật cho JWT authentication trong NestJS REST API.