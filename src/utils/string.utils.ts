/**
 * Capitaliza a primeira letra de cada palavra
 *
 * @param str - String a ser capitalizada
 * @returns A string com a primeira letra de cada palavra capitalizada
 *
 * @example
 * ```ts
 * import { capitalize } from 'example-lib';
 * const result = capitalize('hello world');
 * console.log(result); // Hello World
 * ```
 */
export function capitalize(str: string): string {
	return str
		.split(" ")
		.map((word) => word.charAt(0).toUpperCase() + word.slice(1))
		.join(" ");
}

/**
 * Inverte uma string
 *
 * @param str - String a ser invertida
 * @returns A string invertida
 *
 * @example
 * ```ts
 * import { reverseString } from 'example-lib';
 * const result = reverseString('hello');
 * console.log(result); // olleh
 * ```
 */
export function reverseString(str: string): string {
	return str.split("").reverse().join("");
}
