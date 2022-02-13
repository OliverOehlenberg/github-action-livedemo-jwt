import * as core from '@actions/core';

async function run() {
    const secret: string = core.getInput('secret');
    const issuer: string = core.getInput('issuer');
    const audience: string = core.getInput('audience');
    const validDays: number = +core.getInput('validDays') || 14;
    const offline: string = core.getInput('offline') || 'NO';
    const contact: string = core.getInput('contact');
    const devenv: string = core.getInput('devenv') || 'NO';    
    try {
    
    } catch (err) {
     
    }
  }