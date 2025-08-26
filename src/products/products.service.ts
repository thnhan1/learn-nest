import { Body, Injectable, NotFoundException, Param, ParseIntPipe } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { CreateProductDto } from './dto/create-product.dto';
import { UpdateProductDto } from './dto/update-product.dto';

@Injectable()
export class ProductsService {
    constructor(private readonly prisma: PrismaService) {}

    async createProduct(data: CreateProductDto) {
        return await this.prisma.product.create({
            data: { ...data },
        });
    }

    async getAllProducts(page: number, limit: number, activeOnly: boolean) {
        const products = await this.prisma.product.findMany({
            skip: (page - 1) * limit,
            take: limit,
        });
        return products;
    }

    async getProductById(id: number) {
        const  product =  await this.prisma.product.findUnique({
            where: { id },
        });
        if (!product) {
            throw new NotFoundException('Product not found');
        }
        return product;
    }

    async updateProduct(@Param('id', ParseIntPipe) id: number, @Body() data: UpdateProductDto) {
        const product = await this.prisma.product.findUnique({
            where: { id }
        })
        if (!product) {
            throw new NotFoundException('Product not found');
        }
        return await this.prisma.product
        .update({
            where: { id },
            data: {...data}
        })
    }

    async deleteProduct(id: number) {
        const product = await this.prisma.product.findUnique({
            where: { id }
        })
        if (!product) {
            throw new NotFoundException('Product not found');
        }
        await this.prisma.product.delete({
            where: { id }
        });
    }

    async searchProducts(ids: number[]) {
        const products = await this.prisma.product.findMany({
            where: {
                id: { in: ids }
            },
            select: {
                id: true,
                name: true,
                price: true,
            }
        })

        if (!products.length) {
            throw new NotFoundException('Products not found');
        }
        return products;
    }
}
