import { NextRequest, NextResponse } from 'next/server';
import fs from 'fs';
import { Agent } from 'undici';

// Enforce Node.js runtime to allow file system access for the certificate bundle
export const dynamic = 'force-dynamic';

const certPath = process.env.MTLS_PFX_PATH;
const passphrase = process.env.MTLS_PASSPHRASE;
const rustNodeUrl = process.env.RUST_NODE_URL;

// FATAL BOOT CHECK: Fail-closed if production environment is not configured.
if (!certPath || !fs.existsSync(certPath)) {
  throw new Error("FATAL: MTLS_PFX_PATH is missing or invalid. Next.js proxy cannot boot without mTLS client certificates.");
}
if (!rustNodeUrl) {
  throw new Error("FATAL: RUST_NODE_URL environment variable is missing.");
}

const pfxData = fs.readFileSync(certPath);

// Configure the Node.js Undici Dispatcher with the strict mTLS context
const agent = new Agent({
  connect: {
    pfx: pfxData,
    passphrase: passphrase,
    rejectUnauthorized: process.env.NODE_ENV === 'production', 
  }
});

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ route: string[] }> }
) {
  const resolvedParams = await params;
  const targetRoute = resolvedParams.route.join('/');
  
  try {
    const response = await fetch(`${rustNodeUrl}/${targetRoute}`, {
      method: 'GET',
      headers: {
        'Accept': 'application/json',
      },
      // @ts-ignore - Next.js fetch typings lag behind Undici features, but it executes correctly in Node 18+
      dispatcher: agent, 
    });

    const data = await response.json();
    return NextResponse.json(data, { status: response.status });
  } catch (error: any) {
    console.error(`[mTLS Proxy Error] /${targetRoute}:`, error.message);
    return NextResponse.json({ error: "Secure Node Unreachable", detail: error.message }, { status: 502 });
  }
}