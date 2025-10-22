"""
Key Scrambler - Scrambles keyboard input for chaos mode
"""

import random


class KeyScrambler:
    """
    Scrambles keyboard input by remapping alphanumeric keys.
    Uses consistent per-session mapping for predictable chaos.
    """

    def __init__(self):
        """Initialize the key scrambler with a consistent random mapping"""
        self._mapping = self._generate_mapping()

    def _generate_mapping(self):
        """
        Generate a consistent random mapping for alphanumeric keys.
        Only maps letters (A-Z) and numbers (0-9).

        Returns:
            dict: Mapping of original VK code to scrambled VK code
        """
        mapping = {}

        # Virtual key codes for A-Z (0x41-0x5A)
        letters = list(range(0x41, 0x5B))  # A-Z
        scrambled_letters = letters.copy()
        random.shuffle(scrambled_letters)

        for original, scrambled in zip(letters, scrambled_letters):
            mapping[original] = scrambled

        # Virtual key codes for 0-9 (0x30-0x39)
        numbers = list(range(0x30, 0x3A))  # 0-9
        scrambled_numbers = numbers.copy()
        random.shuffle(scrambled_numbers)

        for original, scrambled in zip(numbers, scrambled_numbers):
            mapping[original] = scrambled

        return mapping

    def scramble_key(self, vk_code):
        """
        Scramble a virtual key code.

        Args:
            vk_code: Original virtual key code

        Returns:
            int: Scrambled virtual key code (or original if not alphanumeric)
        """
        # Return scrambled key if it's in our mapping, otherwise pass through
        return self._mapping.get(vk_code, vk_code)

    def is_scrambleable(self, vk_code):
        """
        Check if a key code can be scrambled.

        Args:
            vk_code: Virtual key code to check

        Returns:
            bool: True if the key is alphanumeric and can be scrambled
        """
        return vk_code in self._mapping
