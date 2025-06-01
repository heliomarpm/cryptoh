import { describe, it, expect } from 'vitest';

import { capitalize, reverseString } from '../src/utils';

describe('Utils: stringUtils', () => {
  describe('capitalize()', () => {
    it('deve lidar com strings vazias', () => {
      expect(capitalize('')).toBe('');
    });

    it('deve capitalizar múltiplas palavras', () => {
      expect(capitalize('foo bar baz')).toBe('Foo Bar Baz');
    });
  });

  describe('reverseString()', () => {
    it('deve inverter strings Unicode', () => {
      expect(reverseString('olá')).toBe('álo');
    });
  });
});