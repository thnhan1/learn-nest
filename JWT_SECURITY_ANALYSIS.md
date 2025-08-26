# Phân tích JWT Security cho NestJS REST API

## Tổng quan
Tài liệu này phân tích chi tiết các file và thành phần cần thiết để triển khai JWT (JSON Web Token) security cho ứng dụng NestJS REST API một cách bảo mật và hiệu quả.

## 🏗️ Cấu trúc thư mục JWT Security

```
src/
├── auth/                          # Module xác thực chính
│   ├── auth.module.ts            # Cấu hình JWT module
│   ├── auth.service.ts           # Logic xác thực và tạo token
│   ├── auth.controller.ts        # API endpoints cho authentication
│   ├── constants.ts              # Cấu hình JWT secret
│   └── dto/                      # Data Transfer Objects
│       ├── login.dto.ts          # Validation cho đăng nhập
│       └── register.dto.ts       # Validation cho đăng ký
├── guard/                        # Guards bảo vệ routes
│   ├── auth.guard.ts            # JWT verification guard
│   └── roles.guard.ts           # Role-based access control
├── decorator/                    # Custom decorators
│   ├── public.decorator.ts      # Đánh dấu route public
│   ├── user.decorator.ts        # Trích xuất user từ request
│   └── roles.decorator.ts       # Định nghĩa roles yêu cầu
├── users/                       # Module quản lý user
│   ├── users.module.ts          # User module configuration
│   └── users.service.ts         # Database operations cho user
├── app.module.ts                # Cấu hình global guards
└── main.ts                      # CORS và global pipes
```

## 📋 Chi tiết các thành phần

### 1. Core Authentication Module

#### `src/auth/auth.module.ts`
**Mục đích:** Cấu hình chính cho JWT authentication
```typescript
@Module({
    imports: [
        UsersModule,
        JwtModule.register({
            global: true,              // JWT module có thể dùng global
            secret: jwtConstants.secret, // Secret key để sign/verify token
            signOptions: {
                expiresIn: '1h',       // Token hết hạn sau 1 giờ
            },
        }),
    ],
    controllers: [AuthController],
    providers: [AuthService],
})
```

**Các điểm quan trọng:**
- Import `JwtModule` với cấu hình global
- Đặt secret key và thời gian hết hạn token
- Kết nối với UsersModule để quản lý thông tin user

#### `src/auth/constants.ts`
**Mục đích:** Lưu trữ các hằng số bảo mật
```typescript
export const jwtConstants = {
    secret: 'superSecretkeylalls', // ⚠️ Nên sử dụng environment variable
};
```

**Best Practice:**
- Không hardcode secret trong code
- Sử dụng `process.env.JWT_SECRET`
- Secret phải đủ phức tạp và dài

#### `src/auth/auth.service.ts`
**Mục đích:** Logic nghiệp vụ cho authentication
```typescript
@Injectable()
export class AuthService {
    async register(email: string, password: string, role: Role = Role.USER) {
        const hash = await bcrypt.hash(password, 10); // Hash password với bcrypt
        return this.usersService.create({ email, password: hash, role });
    }

    async signIn(email: string, pass: string): Promise<{ access_token: string }> {
        const user = await this.usersService.findByEmail(email);
        if (!user || !(await bcrypt.compare(pass, user.password))) {
            throw new UnauthorizedException();
        }
        const payload = { sub: user.id, email: user.email, role: user.role };
        return {
            access_token: await this.jwtService.signAsync(payload, {
                secret: jwtConstants.secret,
            }),
        };
    }
}
```

**Tính năng chính:**
- Hash password bằng bcrypt (salt rounds = 10)
- Xác thực user và tạo JWT token
- Payload chứa: user ID, email, role

### 2. Security Guards

#### `src/guard/auth.guard.ts`
**Mục đích:** Bảo vệ routes với JWT verification
```typescript
@Injectable()
export class AuthGuard implements CanActivate {
    async canActivate(context: ExecutionContext): Promise<boolean> {
        // Kiểm tra nếu route được đánh dấu là public
        const isPublic = this.reflector.getAllAndOverride<boolean>(
            IS_PUBLIC_KEY,
            [context.getHandler(), context.getClass()],
        );

        if (isPublic) {
            return true; // Cho phép truy cập public routes
        }

        // Trích xuất token từ Authorization header
        const request = context.switchToHttp().getRequest();
        const token = this.extractTokenFromHeader(request);
        
        if (!token) {
            throw new UnauthorizedException();
        }

        try {
            // Verify JWT token
            const payload = await this.jwtService.verifyAsync(token, {
                secret: jwtConstants.secret,
            });
            
            // Lấy thông tin user và gán vào request
            const user = await this.usersService.findById(payload.sub);
            if (!user) {
                throw new UnauthorizedException();
            }
            request['user'] = user;
        } catch {
            throw new UnauthorizedException();
        }

        return true;
    }

    private extractTokenFromHeader(request: Request): string | undefined {
        const [type, token] = request.headers.authorization?.split(' ') ?? [];
        return type === 'Bearer' ? token : undefined;
    }
}
```

**Chức năng chính:**
- Kiểm tra public routes
- Trích xuất Bearer token từ header
- Verify JWT token
- Load user info vào request object

#### `src/guard/roles.guard.ts`
**Mục đích:** Role-based access control
```typescript
@Injectable()
export class RolesGuard implements CanActivate {
    canActivate(context: ExecutionContext): boolean {
        const requiredRoles = this.reflector.getAllAndOverride<string[]>(
            ROLES_KEY,
            [context.getHandler(), context.getClass()],
        );
        
        if (!requiredRoles) {
            return true; // Không yêu cầu role cụ thể
        }
        
        const { user } = context.switchToHttp().getRequest();
        return requiredRoles.includes(user?.role);
    }
}
```

### 3. Custom Decorators

#### `src/decorator/public.decorator.ts`
**Mục đích:** Đánh dấu routes không cần authentication
```typescript
export const IS_PUBLIC_KEY = 'isPublic';
export const Public = () => SetMetadata(IS_PUBLIC_KEY, true);
```

**Sử dụng:**
```typescript
@Public()
@Post('login')
signIn(@Body() dto: LoginDto) {
    return this.authService.signIn(dto.email, dto.password);
}
```

#### `src/decorator/user.decorator.ts`
**Mục đích:** Trích xuất user từ request object
```typescript
export const User = createParamDecorator(
    (_data: unknown, ctx: ExecutionContext) => {
        const request = ctx.switchToHttp().getRequest();
        return request.user;
    },
);
```

**Sử dụng:**
```typescript
@Get('profile')
getProfile(@User() user: any) {
    return user;
}
```

#### `src/decorator/roles.decorator.ts`
**Mục đích:** Định nghĩa roles yêu cầu cho route
```typescript
export const ROLES_KEY = 'roles';
export const Roles = (...roles: string[]) => SetMetadata(ROLES_KEY, roles);
```

**Sử dụng:**
```typescript
@Roles('ADMIN')
@Get('admin-only')
adminOnlyRoute() {
    return 'Only admins can access this';
}
```

### 4. Data Transfer Objects (DTOs)

#### `src/auth/dto/login.dto.ts`
**Mục đích:** Validation cho login request
```typescript
export class LoginDto {
    @IsEmail()
    email: string;

    @IsString()
    @MinLength(6)
    password: string;
}
```

#### `src/auth/dto/register.dto.ts`
**Mục đích:** Validation cho register request
```typescript
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

### 5. Global Configuration

#### `src/app.module.ts`
**Mục đích:** Cấu hình global guards
```typescript
@Module({
    providers: [
        {
            provide: APP_GUARD,
            useClass: AuthGuard,    // AuthGuard được áp dụng global
        },
        {
            provide: APP_GUARD,
            useClass: RolesGuard,   // RolesGuard được áp dụng global
        },
    ],
})
```

#### `src/main.ts`
**Mục đích:** Cấu hình CORS và validation
```typescript
const app = await NestFactory.create(AppModule, {
    cors: {
        origin: 'http://localhost:5173',
        methods: ['POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'],
        allowedHeaders: ['Content-Type', 'Authorization'], // Cho phép Authorization header
        credentials: true,
    },
});

app.useGlobalPipes(
    new ValidationPipe({
        whitelist: true,
        forbidNonWhitelisted: true,
        transform: true,
    }),
);
```

## 📦 Dependencies cần thiết

### Production Dependencies
```json
{
    "@nestjs/common": "^11.0.1",     // Core NestJS framework
    "@nestjs/core": "^11.0.1",       // Core NestJS functionality
    "@nestjs/jwt": "^11.0.0",        // JWT integration cho NestJS
    "@prisma/client": "^6.14.0",     // Database ORM client
    "bcryptjs": "^3.0.2",            // Password hashing
    "class-transformer": "^0.5.1",   // DTO transformation
    "class-validator": "^0.14.2",    // DTO validation
    "reflect-metadata": "^0.2.2"     // Metadata reflection
}
```

### Development Dependencies
```json
{
    "@types/bcryptjs": "^2.4.2",     // TypeScript types cho bcryptjs
    "@types/express": "^5.0.0",      // TypeScript types cho Express
    "@types/node": "^22.10.7"        // Node.js TypeScript types
}
```

## 🔐 Security Best Practices

### 1. JWT Secret Management
```typescript
// ❌ Không nên hardcode
const jwtConstants = {
    secret: 'superSecretkeylalls'
};

// ✅ Sử dụng environment variables
const jwtConstants = {
    secret: process.env.JWT_SECRET || 'fallback-secret'
};
```

### 2. Password Hashing
```typescript
// ✅ Sử dụng bcrypt với salt rounds phù hợp
const hash = await bcrypt.hash(password, 12); // 12 rounds cho production
```

### 3. Token Expiration
```typescript
// ✅ Đặt thời gian hết hạn hợp lý
JwtModule.register({
    signOptions: {
        expiresIn: '15m',        // Access token ngắn hạn
    },
})

// Cân nhắc implement refresh token cho session dài hạn
```

### 4. CORS Configuration
```typescript
// ✅ Cấu hình CORS cụ thể cho production
cors: {
    origin: process.env.FRONTEND_URL,
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
}
```

## 🚀 API Endpoints

### Authentication Endpoints
```
POST /auth/register  - Đăng ký user mới (Public)
POST /auth/login     - Đăng nhập (Public)
GET  /auth/profile   - Lấy thông tin user (Protected)
```

### Request/Response Examples

#### Register Request
```json
{
    "email": "user@example.com",
    "password": "password123",
    "role": "USER"
}
```

#### Login Request
```json
{
    "email": "user@example.com",
    "password": "password123"
}
```

#### Login Response
```json
{
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

#### Protected Request Headers
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

## 🗄️ Database Schema

### User Model (Prisma)
```prisma
enum Role {
  USER
  ADMIN
}

model User {
  id        Int      @id @default(autoincrement())
  email     String   @unique
  password  String   // Hashed password
  role      Role     @default(USER)
  createdAt DateTime @default(now())
  updatedAt DateTime @updatedAt
}
```

## 📝 Cách sử dụng trong Controller

```typescript
@Controller('protected')
export class ProtectedController {
    // Route cần authentication và role ADMIN
    @Roles('ADMIN')
    @Get('admin-only')
    adminOnly(@User() user: any) {
        return { message: 'Admin access granted', user };
    }

    // Route cần authentication nhưng không cần role cụ thể
    @Get('user-info')
    userInfo(@User() user: any) {
        return user;
    }

    // Route public, không cần authentication
    @Public()
    @Get('public')
    publicRoute() {
        return { message: 'This is a public route' };
    }
}
```

## ⚡ Testing với JWT

### Test Authentication
```bash
# Đăng ký
curl -X POST http://localhost:3000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password123"}'

# Đăng nhập
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password123"}'

# Truy cập protected route
curl -X GET http://localhost:3000/auth/profile \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

## 🔧 Troubleshooting

### Lỗi thường gặp:

1. **"No exported member 'Role'"**
   - Chạy `npx prisma generate` để tạo Prisma client

2. **"UnauthorizedException"**
   - Kiểm tra token có được gửi đúng format không
   - Xác minh token chưa hết hạn
   - Đảm bảo secret key đúng

3. **CORS errors**
   - Cấu hình CORS trong main.ts
   - Thêm Authorization vào allowedHeaders

## 📚 Tài liệu tham khảo

- [NestJS JWT Documentation](https://docs.nestjs.com/security/authentication)
- [JWT Best Practices](https://auth0.com/blog/a-look-at-the-latest-draft-for-jwt-bcp/)
- [bcrypt Documentation](https://github.com/kelektiv/node.bcrypt.js)
- [Prisma Documentation](https://www.prisma.io/docs/)

---

**Lưu ý:** Đây là phân tích dựa trên implementation hiện tại. Đối với production, cần cân nhắc thêm các tính năng như refresh token, rate limiting, và logging bảo mật.