/*The following class:
 * 
 * VaultSession manages the unlocked state of the vault.
 *
 * - Locked by default.
 * - When unlocked, it holds the derived AES key in memory.
 * - When locked, the key is securely wiped and no operations are possible.
*/
