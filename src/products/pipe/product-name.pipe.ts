import { ArgumentMetadata, Injectable, PipeTransform } from '@nestjs/common';

@Injectable()
export class ProductNamePipe implements PipeTransform {
    transform(value: any, metadata: ArgumentMetadata) {

        if (metadata.type !== 'body') {
            return value;
        }
        let name = value.name;
        // trim space
        name = name.trim();
        if (name && typeof name === 'string') {
            value.name = name[0].toUpperCase() + name.slice(1);
        }
        return value;
    }
}