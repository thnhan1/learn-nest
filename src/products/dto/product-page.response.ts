import { ProductEntity } from "../entity/product.entity";

export class ProductPageResponse {
    page: number;
    limit: number;
    items: ProductEntity[];
}