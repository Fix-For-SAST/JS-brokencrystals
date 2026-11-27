import { createClient, createChannel } from 'nice-grpc-web';
import {
  ProductsServiceDefinition,
  type ViewProductResponse,
  type ProductsServiceClient
} from '../generated/products';
import {
  type TestimonialsCountResponse,
  TestimonialsServiceDefinition,
  type TestimonialsServiceClient
} from '../generated/testimonials';
import {
  FileServiceDefinition,
  type ReadFileResponse,
  type FileServiceClient
} from '../generated/file';
import {
  OsServiceDefinition,
  type RunCommandResponse,
  type OsServiceClient
} from '../generated/os';

export class GrpcClient {
  private static instance: GrpcClient;

  public products: ProductsServiceClient;
  public testimonials: TestimonialsServiceClient;
  public file: FileServiceClient;
  public os: OsServiceClient;

  private constructor() {
    const baseUrl = `${window.location.origin}/grpc`;
    const channel = createChannel(baseUrl);

    this.products = createClient(ProductsServiceDefinition, channel);
    this.testimonials = createClient(TestimonialsServiceDefinition, channel);
    this.file = createClient(FileServiceDefinition, channel);
    this.os = createClient(OsServiceDefinition, channel);
  }

  public static getInstance(): GrpcClient {
    if (!GrpcClient.instance) {
      GrpcClient.instance = new GrpcClient();
    }
    return GrpcClient.instance;
  }
}

export async function viewProductGrpc(
  productName: string
): Promise<ViewProductResponse> {
  const client = GrpcClient.getInstance();
  return client.products.viewProduct({ productName });
}

export async function getTestimonialsCountGrpc(
  query: string = 'select count(1) as count from testimonial'
): Promise<TestimonialsCountResponse> {
  const client = GrpcClient.getInstance();
  return client.testimonials.testimonialsCount({ query });
}

// Allowlist of permitted file paths for CWE-73 remediation
const ALLOWED_FILE_PATHS = [
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

export async function readFileGrpc(path: string): Promise<ReadFileResponse> {
  // CWE-73: Validate path against allowlist
  const safeIndex = ALLOWED_FILE_PATHS.indexOf(path);
  if (safeIndex === -1) {
    throw new Error('Operation not permitted: invalid file path');
  }
  const safePath = ALLOWED_FILE_PATHS.at(safeIndex);

  const client = GrpcClient.getInstance();
  return client.file.readFile({ path: safePath });
}

export async function getSpawnDataGrpc(
  command: string = 'pwd'
): Promise<RunCommandResponse> {
  const client = GrpcClient.getInstance();
  return client.os.runCommand({ command });
}
