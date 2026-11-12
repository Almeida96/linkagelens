package demo.checkout;

import demo.pricing.Tariff;

public final class Checkout {
    public static void main(String[] args) {
        long total = new Tariff().quote(540L, 2);
        System.out.println("Order total: " + total + " cents");
    }
}
