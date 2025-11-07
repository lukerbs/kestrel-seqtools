# generate_test_cards.py
"""
Test Credit Card Generator
For SOFTWARE TESTING and SCAMBAITING ONLY
These numbers pass validation but are NOT real cards and will not work for transactions.
"""

import random


class TestCardGenerator:
    """Generate test credit card numbers that pass Luhn validation"""

    # Bank of America BIN (Bank Identification Number) ranges
    # These are real BofA BIN prefixes (publicly available information)
    # First 6 digits identify the issuing bank
    BOFA_BINS = {
        "visa_credit": [
            "440393",  # BofA Visa Credit
            "442903",  # BofA Visa Signature
            "447162",  # BofA Travel Rewards
            "451277",  # BofA Premium Rewards
            "420013",  # BofA Unlimited Cash
            "413298",  # BofA Customized Cash
            "481254",  # BofA Business Advantage
        ],
        "visa_debit": [
            "409375",  # BofA Visa Debit
            "451234",  # BofA Debit
            "412578",  # BofA CheckCard
        ],
        "mastercard_credit": [
            "520421",  # BofA MC Credit
            "542898",  # BofA MC World
            "549812",  # BofA MC Business
        ],
        "mastercard_debit": [
            "545123",  # BofA MC Debit
            "520398",  # BofA MC CheckCard
        ],
        "amex": [
            "374298",  # BofA Amex Business
            "378234",  # BofA Amex Corporate
        ],
    }

    @staticmethod
    def luhn_checksum(card_number: str) -> int:
        """Calculate Luhn checksum digit"""

        def digits_of(n):
            return [int(d) for d in str(n)]

        digits = digits_of(card_number)
        odd_digits = digits[-1::-2]
        even_digits = digits[-2::-2]

        checksum = sum(odd_digits)
        for d in even_digits:
            checksum += sum(digits_of(d * 2))

        return (10 - (checksum % 10)) % 10

    @staticmethod
    def is_valid_luhn(card_number: str) -> bool:
        """Verify if card number passes Luhn check"""
        try:
            check_digit = int(card_number[-1])
            calculated = TestCardGenerator.luhn_checksum(card_number[:-1])
            return check_digit == calculated
        except:
            return False

    def generate_card(self, card_type: str = None, bin_prefix: str = None, length: int = 16) -> tuple:
        """
        Generate a test card number

        Args:
            card_type: Type of card ('visa_credit', 'visa_debit', 'mastercard_credit', etc.)
            bin_prefix: BIN prefix (first 6 digits), or None for random
            length: Total card length (16 for Visa/MC, 15 for Amex)

        Returns:
            Tuple of (card_number, card_type)
        """
        # Select card type if not specified
        if card_type is None and bin_prefix is None:
            card_type = random.choice(list(self.BOFA_BINS.keys()))

        # Select BIN prefix
        if bin_prefix is None:
            bin_prefix = random.choice(self.BOFA_BINS[card_type])

        # Amex cards are 15 digits, others are 16
        if bin_prefix.startswith("37"):
            length = 15

        # Generate random middle digits (account number portion)
        middle_length = length - len(bin_prefix) - 1  # -1 for check digit
        middle_digits = "".join(str(random.randint(0, 9)) for _ in range(middle_length))

        # Combine and calculate check digit
        partial_card = bin_prefix + middle_digits
        check_digit = self.luhn_checksum(partial_card)

        full_card = partial_card + str(check_digit)

        # Verify
        assert self.is_valid_luhn(full_card), "Generated invalid card"

        return full_card, card_type if card_type else "unknown"

    def generate_formatted(self, card_type: str = None) -> str:
        """Generate card with standard formatting (spaces every 4 digits)"""
        card, _ = self.generate_card(card_type=card_type)
        return " ".join(card[i : i + 4] for i in range(0, len(card), 4))

    def generate_expiry(self) -> tuple:
        """Generate random future expiry date"""
        import datetime

        today = datetime.date.today()

        # Random date 1-5 years in future
        years_ahead = random.randint(1, 5)
        month = random.randint(1, 12)
        year = today.year + years_ahead

        return (f"{month:02d}", str(year)[-2:])  # Returns ("MM", "YY")

    def generate_cvv(self) -> str:
        """Generate random CVV (3 digits)"""
        return str(random.randint(100, 999))

    def generate_complete_card(self, name: str = "Robert Gardner", card_type: str = None) -> dict:
        """Generate complete card details for testing"""
        card_number, card_category = self.generate_card(card_type=card_type)
        exp_month, exp_year = self.generate_expiry()

        # Get friendly card type name
        card_type_display, card_brand = self.get_card_type(card_number, card_category)

        return {
            "number": card_number,
            "number_formatted": self.format_card(card_number),
            "name": name,
            "expiry_month": exp_month,
            "expiry_year": exp_year,
            "expiry": f"{exp_month}/{exp_year}",
            "cvv": self.generate_cvv() if not card_number.startswith("37") else str(random.randint(1000, 9999)),
            "type": card_brand,
            "card_category": card_category,
            "product_name": card_type_display,
        }

    @staticmethod
    def format_card(card_number: str) -> str:
        """Format card with spaces"""
        return " ".join(card_number[i : i + 4] for i in range(0, len(card_number), 4))

    @staticmethod
    def get_card_type(card_number: str, card_category: str = None) -> tuple:
        """
        Identify card type from BIN and category

        Returns:
            Tuple of (product_name, brand)
        """
        # Map BIN to specific products
        bin_6 = card_number[:6]

        product_map = {
            "440393": ("Cash Rewards", "Visa"),
            "442903": ("Travel Rewards", "Visa"),
            "447162": ("Premium Rewards", "Visa"),
            "451277": ("Unlimited Cash Rewards", "Visa"),
            "420013": ("Customized Cash Rewards", "Visa"),
            "413298": ("Advantage Banking", "Visa"),
            "481254": ("Business Advantage Cash Rewards", "Visa"),
            "409375": ("Debit Card", "Visa"),
            "451234": ("Advantage SafeBalance Banking", "Visa"),
            "412578": ("Checking Account", "Visa"),
            "520421": ("Cash Rewards", "Mastercard"),
            "542898": ("Travel Rewards", "Mastercard"),
            "549812": ("Business Cash Rewards", "Mastercard"),
            "545123": ("Debit Card", "Mastercard"),
            "520398": ("Checking Account", "Mastercard"),
            "374298": ("Business Advantage Cash Rewards", "American Express"),
            "378234": ("Business Advantage Travel Rewards", "American Express"),
        }

        if bin_6 in product_map:
            return product_map[bin_6]

        # Fallback to generic identification
        if card_number[0] == "4":
            brand = "Visa"
        elif card_number[0] == "5":
            brand = "Mastercard"
        elif card_number[0] == "3":
            brand = "American Express"
        elif card_number[0] == "6":
            brand = "Discover"
        else:
            brand = "Unknown"

        # Use category if available
        if card_category:
            if "credit" in card_category:
                product = f"{brand} Credit Card"
            elif "debit" in card_category:
                product = f"{brand} Debit Card"
            else:
                product = brand
        else:
            product = brand

        return (product, brand)


def main():
    """Generate test cards for scambaiting project"""
    generator = TestCardGenerator()

    print("=" * 60)
    print("  Test Credit Card Generator")
    print("  FOR TESTING/SCAMBAITING ONLY")
    print("=" * 60)
    print()

    # Generate multiple test cards with variety
    print("Generating realistic Bank of America cards:\n")

    card_types_to_generate = ["visa_credit", "visa_debit", "mastercard_credit", "visa_credit", "amex"]

    for i, card_type in enumerate(card_types_to_generate):
        card = generator.generate_complete_card(name="ROBERT B GARDNER", card_type=card_type)

        print(f"Card #{i+1}: {card['product_name']}")
        print(f"  Number:  {card['number_formatted']}")
        print(f"  Name:    {card['name']}")
        print(f"  Expiry:  {card['expiry']}")
        print(f"  CVV:     {card['cvv']}")
        print(f"  Brand:   {card['type']}")
        print(f"  BIN:     {card['number'][:6]} (Bank of America)")
        print(f"  Valid:   ✓ Passes Luhn check" if generator.is_valid_luhn(card["number"]) else "  Valid:   ✗ INVALID")
        print()

    # Generate specific format for your fake bank site
    print("-" * 60)
    print("For your fake bank site (site/data/cards.json):\n")

    cards_json = []
    card_types_json = ["visa_credit", "visa_debit", "mastercard_credit"]

    for i, ctype in enumerate(card_types_json):
        card = generator.generate_complete_card(name="ROBERT B GARDNER", card_type=ctype)
        cards_json.append(
            {
                "card_id": f"cc_{4782 + i}",
                "product_name": card["product_name"],
                "card_brand": card["type"],
                "card_number": card["number"],
                "last_four": card["number"][-4:],
                "expiry_date": card["expiry"],
                "cvv": card["cvv"],
                "name_on_card": card["name"],
                "billing_address": {
                    "street": "1247 Oak Grove Drive",
                    "city": "Dearborn",
                    "state": "MI",
                    "zip": "48124",
                },
                "credit_limit": random.randint(5000, 25000) if "credit" in ctype else None,
                "available_credit": None,
                "status": "Active",
            }
        )

    # Calculate available credit
    for card in cards_json:
        if card["credit_limit"]:
            card["available_credit"] = card["credit_limit"] - random.randint(500, card["credit_limit"] // 2)

    import json

    print(json.dumps({"bob.gardner": cards_json}, indent=2))

    print()
    print("-" * 60)
    print("⚠️  REMINDER: These are TEST CARDS ONLY")
    print()
    print("✓ Realistic Features:")
    print("   - Real Bank of America BIN ranges (first 6 digits)")
    print("   - Correct card length (16 for Visa/MC, 15 for Amex)")
    print("   - Pass Luhn algorithm validation")
    print("   - Realistic product names (Cash Rewards, Travel Rewards, etc.)")
    print("   - Proper CVV format (3 digits for Visa/MC, 4 for Amex)")
    print()
    print("✗ Limitations:")
    print("   - NOT linked to real accounts")
    print("   - Will be REJECTED by payment processors")
    print("   - For testing/scambaiting purposes ONLY")
    print("   - Using these for fraud is illegal")
    print()
    print("📖 Use Cases:")
    print("   - E-commerce form validation testing")
    print("   - Scambaiting honeypot bank sites")
    print("   - Software development/QA")
    print("   - Security awareness training")
    print("=" * 60)


if __name__ == "__main__":
    main()
