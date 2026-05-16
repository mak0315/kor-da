// Temporary type declarations to suppress IDE errors before 'npm install' is run

declare module 'next' {
  export type NextConfig = any;
  export type Metadata = any;
}

declare module 'next/server' {
  export class NextResponse {
    static json(body: any, init?: any): any;
    static next(): any;
    constructor(body?: any, init?: any);
  }
  export type NextRequest = any;
}

declare module 'next/font/google' {
  export function Inter(options: any): any;
}

declare module 'jsonwebtoken' {
  export function sign(payload: any, secretOrPrivateKey: string, options?: any): string;
  export function verify(token: string, secretOrPublicKey: string, options?: any): any;
}

declare namespace NodeJS {
  interface ProcessEnv {
    [key: string]: string | undefined;
  }
}

declare var process: {
  env: NodeJS.ProcessEnv;
};

declare namespace React {
  type ReactNode = any;
}

declare namespace JSX {
  interface IntrinsicElements {
    [elemName: string]: any;
  }
}
