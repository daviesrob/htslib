/* The MIT License

   Copyright (C) 2010, 2013 Genome Research Ltd.
   Copyright (C) 2011 Attractive Chaos <attractor@live.co.uk>

   Permission is hereby granted, free of charge, to any person obtaining
   a copy of this software and associated documentation files (the
   "Software"), to deal in the Software without restriction, including
   without limitation the rights to use, copy, modify, merge, publish,
   distribute, sublicense, and/or sell copies of the Software, and to
   permit persons to whom the Software is furnished to do so, subject to
   the following conditions:

   The above copyright notice and this permission notice shall be
   included in all copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
   EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
   MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
   NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
   BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
   ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
   CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
   SOFTWARE.
*/

#ifndef HTSLIB_KFUNC_H
#define HTSLIB_KFUNC_H

#ifdef __cplusplus
extern "C" {
#endif

/* Log gamma function
 * \log{\Gamma(z)}
 * AS245, 2nd algorithm, http://lib.stat.cmu.edu/apstat/245
 */
static inline double kf_lgamma(double z) {
    double hts_kf_lgamma(double z);
    return hts_kf_lgamma(z);
}

/* complementary error function
 * \frac{2}{\sqrt{\pi}} \int_x^{\infty} e^{-t^2} dt
 * AS66, 2nd algorithm, http://lib.stat.cmu.edu/apstat/66
 */
static inline double kf_erfc(double x) {
    double hts_kf_erfc(double x);
    return hts_kf_erfc(x);
}

/* The following computes regularized incomplete gamma functions.
 * Formulas are taken from Wiki, with additional input from Numerical
 * Recipes in C (for modified Lentz's algorithm) and AS245
 * (http://lib.stat.cmu.edu/apstat/245).
 *
 * A good online calculator is available at:
 *
 *   http://www.danielsoper.com/statcalc/calc23.aspx
 *
 * It calculates upper incomplete gamma function, which equals
 * kf_gammaq(s,z)*tgamma(s).
 */

static inline double kf_gammap(double s, double z) {
    double hts_kf_gammap(double s, double z);
    return hts_kf_gammap(s, z);
}
static inline double kf_gammaq(double s, double z) {
    double hts_kf_gammaq(double s, double z);
    return hts_kf_gammaq(s, z);
}

/* Regularized incomplete beta function. The method is taken from
 * Numerical Recipe in C, 2nd edition, section 6.4. The following web
 * page calculates the incomplete beta function, which equals
 * kf_betai(a,b,x) * gamma(a) * gamma(b) / gamma(a+b):
 *
 *   http://www.danielsoper.com/statcalc/calc36.aspx
 */
static inline double kf_betai(double a, double b, double x) {
    double hts_kf_betai(double a, double b, double x);
    return hts_kf_betai(a, b, x);
}

/*
 *    n11  n12  | n1_
 *    n21  n22  | n2_
 *   -----------+----
 *    n_1  n_2  | n
 */
static inline double kt_fisher_exact(int n11, int n12, int n21, int n22, double *left_, double *right_, double *two) {
    double hts_kt_fisher_exact(int n11, int n12, int n21, int n22, double *left_, double *right_, double *two);
    return hts_kt_fisher_exact(n11, n12, n21, n22, left_, right_, two);
}

#ifdef __cplusplus
}
#endif

#endif
