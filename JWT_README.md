# JWT Security cho NestJS REST API - Tổng quan

## 📝 Mô tả dự án
Dự án này demo một implementation hoàn chỉnh của JWT (JSON Web Token) authentication và authorization cho ứng dụng NestJS REST API.

## 🏗️ Kiến trúc JWT Security

### Các thành phần chính:
1. **Authentication Module** - Xử lý đăng nhập/đăng ký
2. **JWT Guards** - Bảo vệ routes và kiểm tra quyền
3. **Custom Decorators** - Đánh dấu routes public/private và trích xuất user
4. **DTOs** - Validation input data
5. **Database Schema** - User model với roles

## 📁 Cấu trúc files cần thiết

```
src/
├── auth/
│   ├── auth.module.ts        ✅ Cấu hình JWT module
│   ├── auth.service.ts       ✅ Logic authentication
│   ├── auth.controller.ts    ✅ API endpoints
│   ├── constants.ts          ✅ JWT secret
│   └── dto/
│       ├── login.dto.ts      ✅ Validation login
│       └── register.dto.ts   ✅ Validation register
├── guard/
│   ├── auth.guard.ts         ✅ JWT verification
│   └── roles.guard.ts        ✅ Role-based access
├── decorator/
│   ├── public.decorator.ts   ✅ Public routes
│   ├── user.decorator.ts     ✅ Extract user
│   └── roles.decorator.ts    ✅ Required roles
├── users/
│   ├── users.module.ts       ✅ User module
│   └── users.service.ts      ✅ User operations
├── app.module.ts             ✅ Global guards config
└── main.ts                   ✅ CORS & validation
```

## 🚀 Quick Start

### 1. Cài đặt dependencies
```bash
npm install @nestjs/jwt bcryptjs class-validator class-transformer
npm install -D @types/bcryptjs
```

### 2. Cấu hình environment
```env
JWT_SECRET=your-super-secret-key
DATABASE_URL=postgresql://...
```

### 3. Chạy ứng dụng
```bash
npx prisma generate
npm run start:dev
```

## 🔗 API Endpoints

| Method | Endpoint | Mô tả | Auth Required |
|--------|----------|--------|---------------|
| POST | `/auth/register` | Đăng ký user mới | ❌ Public |
| POST | `/auth/login` | Đăng nhập | ❌ Public |
| GET | `/auth/profile` | Lấy thông tin user | ✅ Protected |

## 💻 Cách sử dụng trong code

### Protect route với JWT
```typescript
@Get('protected')
protectedRoute(@User() user: any) {
    return { message: 'Protected data', user };
}
```

### Public route (không cần JWT)
```typescript
@Public()
@Get('public')
publicRoute() {
    return { message: 'Public data' };
}
```

### Role-based access
```typescript
@Roles('ADMIN')
@Get('admin-only')
adminOnly(@User() user: any) {
    return { message: 'Admin only', user };
}
```

## 🧪 Test API

### Đăng ký
```bash
curl -X POST http://localhost:3000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password123"}'
```

### Đăng nhập
```bash
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password123"}'
```

### Truy cập protected route
```bash
curl -X GET http://localhost:3000/auth/profile \
  -H "Authorization: Bearer <JWT_TOKEN>"
```

## 🔐 Tính năng bảo mật

- ✅ JWT token authentication
- ✅ Password hashing với bcrypt
- ✅ Role-based access control
- ✅ Input validation với class-validator
- ✅ CORS configuration
- ✅ Global guards protection
- ✅ Custom decorators cho flexibility

## 📚 Tài liệu chi tiết

- **[JWT_SECURITY_ANALYSIS.md](./JWT_SECURITY_ANALYSIS.md)** - Phân tích chi tiết từng component
- **[JWT_IMPLEMENTATION_GUIDE.md](./JWT_IMPLEMENTATION_GUIDE.md)** - Hướng dẫn implementation từng bước

## 🛡️ Security Best Practices được áp dụng

1. **JWT Secret Management** - Sử dụng environment variables
2. **Password Security** - bcrypt với salt rounds phù hợp
3. **Token Expiration** - Thiết lập thời gian hết hạn
4. **Input Validation** - class-validator cho tất cả DTOs
5. **CORS Configuration** - Cấu hình origin và headers cụ thể
6. **Global Guards** - Protection cho toàn bộ application

## 🏃‍♂️ Triển khai production

### Environment variables cần thiết:
```env
JWT_SECRET=complex-secret-key-here
DATABASE_URL=postgresql://...
FRONTEND_URL=https://your-frontend.com
PORT=3000
```

### Additional security cho production:
- Sử dụng HTTPS
- Implement refresh tokens
- Add rate limiting
- Security headers
- Logging và monitoring

---

**Tác giả:** NestJS JWT Security Implementation  
**Mục đích:** Demo và học tập JWT authentication trong NestJS