import { describe, it, expect } from 'vitest';

import lib from '../src/index';

describe('Biblioteca Principal', () => {
  it('capitalize() deve capitalizar palavras', () => {
    expect(lib.capitalize('hello world')).toBe('Hello World');
  });

  it('reverseString() deve inverter strings', () => {
    expect(lib.reverseString('123')).toBe('321');
  });
});