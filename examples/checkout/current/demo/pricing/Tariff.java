package demo.pricing;

public final class Tariff {
    public long quote(long cents) {
        return cents;
    }

    public long quote(long cents, int units) {
        return Math.multiplyExact(cents, units);
    }
}
