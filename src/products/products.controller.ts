import { Body, Controller, DefaultValuePipe, Delete, Get, HttpCode, HttpStatus, Param, ParseArrayPipe, ParseBoolPipe, ParseIntPipe, Patch, Post, Query, UseGuards } from '@nestjs/common';
import { CreateProductDto } from './dto/create-product.dto';
import { ProductsService } from './products.service';
import { ProductNamePipe } from './pipe/product-name.pipe';
import { UpdateProductDto } from './dto/update-product.dto';
import { RolesGuard } from 'src/guard/roles.guard';

@UseGuards(RolesGuard)
@Controller('products')
export class ProductsController {
    constructor(private readonly productsService: ProductsService) {}

    @Post()
    async createProducT(@Body(ProductNamePipe) body: CreateProductDto) {
        console.log(body);
        return await this.productsService.createProduct(body);
    }

    @Get()
    async getAllProducts(@Query('page', ParseIntPipe, new DefaultValuePipe(1)) page: number, @Query('limit', ParseIntPipe, new DefaultValuePipe(10)) limit: number, @Query('activeOnly', ParseBoolPipe, new DefaultValuePipe(false)) activeOnly: boolean) {
        console.log(page, limit, activeOnly);
        const items =  await this.productsService.getAllProducts(page, limit, activeOnly);
        return {
            page,
            limit,
            items,
        };
    }

    @Get('search')
    async searchProducts(
        @Query('ids', new ParseArrayPipe({ items: Number, separator: ',', optional: false })) ids: number[]
    ) {
        console.log(ids);
        return await this.productsService.searchProducts(ids);
    }

    @Get(':id')
    async getProductById(@Param('id', new ParseIntPipe({ errorHttpStatusCode: HttpStatus.NOT_ACCEPTABLE })) id: number) {
        return await this.productsService.getProductById(id);
    }

    @Patch(':id')
    async updateProduct(@Param('id', ParseIntPipe) id: number, @Body() data: UpdateProductDto) {
        return await this.productsService.updateProduct(id, data);
    }

    @Delete(':id')
    @HttpCode(HttpStatus.NO_CONTENT)
    async deleteProduct(@Param('id', ParseIntPipe) id : number) {
         await this.productsService.deleteProduct(id)
    }
}
