import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import { AuthGuard } from './guard/auth.guard';

async function bootstrap() {
    const app = await NestFactory.create(AppModule, {
        bodyParser: true,
        cors: {
            origin: 'http://localhost:5173',
            methods: ['POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'],
            allowedHeaders: ['Content-Type', 'Authorization'],
            credentials: true,
        },
    });

    // Global validation pipe
    app.useGlobalPipes(
        new ValidationPipe({
            whitelist: true, // exclude any properties not in dto
            forbidNonWhitelisted: true, // not throw an error if a property is not in dto
            transform: true, // auto transform data to types of dto
            transformOptions: {
                enableImplicitConversion: true, // allow implicit conversion of string to number
            },
        }),
    );

    app.getHttpAdapter().getInstance().set('etag', false);

    await app.listen(process.env.PORT ?? 3000);
}

bootstrap().catch((error) =>
    console.error('Error occurred during bootstrap:', error),
);
