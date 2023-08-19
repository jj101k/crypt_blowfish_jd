#!/usr/bin/ruby -w
class Pi
    def Pi.fraction_bytes(count = 1)
        digits = ""
        hexdigits = %w{0 1 2 3 4 5 6 7 8 9 a b c d e f}
        remainder_b = nil
        remainder_t = nil
        (0 .. 2 * count.to_i).each do
            |k|
            a = 8 * k + 1
            b = 8 * k + 4
            c = 8 * k + 5
            d = 8 * k + 6
            e = 16 ** k

            top = 4 * d * c * b - 2 * d * c * a - 1 * d * b * a - 1 * c * b * a
            bottom = a * b * c * d
            if(remainder_b)
                top = top * remainder_b + remainder_t * 16 * bottom
                bottom = remainder_b * bottom
            end
            pi_digit = top / bottom
            if(remainder_b)
                digits += hexdigits[pi_digit]
            end
            remainder_t = top - pi_digit * bottom
            remainder_b = bottom
            #remainder_t, remainder_b =* (reduce_fraction(remainder_t, remainder_b))
        end
        digits
    end
end
