import { Injectable, Logger } from '@nestjs/common';
import { Readable } from 'stream';
import * as fs from 'fs';
import * as path from 'path';
import { CloudProvidersMetaData } from './cloud.providers.metadata';
import { R_OK } from 'constants';

@Injectable()
export class FileService {
  private readonly logger = new Logger(FileService.name);
  private cloudProviders = new CloudProvidersMetaData();

  // Allowlist of permitted file paths for CWE-73 remediation
  private readonly ALLOWED_FILES = [
    'config/products/crystals/amber.jpg',
    'config/products/crystals/amethyst.jpg',
    'config/products/crystals/axinite.jpg',
    'config/products/crystals/bismuth.jpg',
    'config/products/crystals/emerald.jpg',
    'config/products/crystals/labradorite.jpg',
    'config/products/crystals/opal.jpg',
    'config/products/crystals/pietersite.jpg',
    'config/products/crystals/pyrite.jpg',
    'config/products/crystals/ruby.jpg',
    'config/products/crystals/sapphire.jpg',
    'config/products/crystals/shattuckite.jpg',
    'config/keys/bc_private.key',
    'config/keys/bc_public.crt',
    'config/keys/jku.json',
    'config/keys/jwk.json',
    'config/keys/jwk.key.pem',
    'config/keys/jwk.pub.json',
    'config/keys/jwk.pub.key.pem',
    'config/keys/jwtRS256.key',
    'config/keys/jwtRS256.key.pub',
    'config/keys/jwtRS256.key.pub.pem',
    'config/keys/x509.crt'
  ];

  async getFile(file: string): Promise<Readable> {
    this.logger.log(`Reading file: ${JSON.stringify(file)}`);

    if (file.startsWith('/')) {
      // CWE-73: Validate absolute paths against allowlist
      const safeIndex = this.ALLOWED_FILES.indexOf(file.substring(1));
      if (safeIndex === -1) {
        throw new Error('Operation not permitted');
      }
      const safePath = this.ALLOWED_FILES.at(safeIndex);
      const fullPath = path.resolve(process.cwd(), safePath);
      await fs.promises.access(fullPath, R_OK);

      return fs.createReadStream(fullPath);
    } else if (file.startsWith('http')) {
      const content = await this.cloudProviders.get(file);

      if (content) {
        return Readable.from(content);
      } else {
        throw new Error(`no such file or directory, access '${file}'`);
      }
    } else {
      // CWE-73: Validate relative paths against allowlist
      const safeIndex = this.ALLOWED_FILES.indexOf(file);
      if (safeIndex === -1) {
        throw new Error('Operation not permitted');
      }
      const safePath = this.ALLOWED_FILES.at(safeIndex);
      const fullPath = path.resolve(process.cwd(), safePath);

      await fs.promises.access(fullPath, R_OK);

      return fs.createReadStream(fullPath);
    }
  }

  async deleteFile(file: string): Promise<boolean> {
    if (file.startsWith('/')) {
      throw new Error('cannot delete file from this location');
    } else if (file.startsWith('http')) {
      throw new Error('cannot delete file from this location');
    } else {
      // CWE-73: Validate paths against allowlist
      const safeIndex = this.ALLOWED_FILES.indexOf(file);
      if (safeIndex === -1) {
        throw new Error('Operation not permitted');
      }
      const safePath = this.ALLOWED_FILES.at(safeIndex);
      const fullPath = path.resolve(process.cwd(), safePath);
      await fs.promises.unlink(fullPath);
      return true;
    }
  }
}
