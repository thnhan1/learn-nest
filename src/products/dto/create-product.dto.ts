import { IsNotEmpty, IsNumber, IsString, MaxLength, Min, MinLength } from 'class-validator';

export class CreateProductDto {
    @IsString()
    @MaxLength(100)
    @IsNotEmpty()
    name: string;

    @Min(0)
    @IsNumber()
    price: number;

    @IsString()
    @MaxLength(500)
    description: string;
}
