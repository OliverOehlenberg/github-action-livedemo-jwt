import * as core from '@actions/core';
import * as jose from 'jose';
import * as timestamp from 'unix-timestamp';

async function run() {
  const secret: string = core.getInput('secret');
  const issuer: string = core.getInput('issuer');
  const audience: string = core.getInput('audience');
  const validDays: number = +core.getInput('validDays') || 14;
  const offline: string = core.getInput('offline') || 'NO';
  const contact: string = core.getInput('contact');
  const devenv: string = core.getInput('devenv') || 'NO';

  try {
    var payloadData = {
      iss: issuer,
      aud: audience,
      sub: contact,
      off: offline,
      dev: devenv
    };

    const expDate = new Date();
    expDate.setDate(expDate.getDate() + validDays);
    let utf8Encode = new TextEncoder();

    const jwt = await new jose.SignJWT(payloadData)
      .setProtectedHeader({alg: 'HS256'})
      .setIssuedAt()
      .setExpirationTime(timestamp.fromDate(expDate))
      .sign(utf8Encode.encode(secret));

    console.log(jwt);
    core.setOutput("token", jwt);

  } catch (err) {
    console.error(
      `⚠️ An error happened executing JWT signing...`,
      err?.message ?? err
    );

    core.setFailed(err.message);
    process.abort();
  }
}
