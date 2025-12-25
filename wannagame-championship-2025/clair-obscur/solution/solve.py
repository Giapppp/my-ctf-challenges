from sage.all import *
from Crypto.Util.number import *
from pwn import *

rs = []
ms = []

def random_element_from_basis(M):
    val = 0
    n = M.nrows()
    Fp = M.base_ring()
    for i in range(n):
        val += Fp.random_element() * M[i]
    return val

def random_point():
    while True:
        a, b, c = [Fp.random_element() for _ in range(3)]
        x = Fp["d"].gen()
        f = a * b**2 + b * c**2 + c * x**2 + x * a**2
        r = f.roots()
        if len(r) > 0:
            d = r[0][0]
            return [a, b, c, d]

pari.allocatemem(16 << 29)

while True:
    try:
        nbits = 256
        p = random_prime(2**nbits, lbound=2**(nbits-1))
        Fp = GF(p)

        G0 = random_point()
        L_vec = random_element_from_basis(matrix(Fp, G0).right_kernel_matrix())

        M = matrix(Fp, L_vec)

        basis = M.right_kernel().basis() 
        if len(basis) != 3:
            print("hiahds")
            exit()

        R_plane = PolynomialRing(Fp, 'u,v,w')
        u, v, w = R_plane.gens()

        a = u*basis[0][0] + v*basis[1][0] + w*basis[2][0]
        b = u*basis[0][1] + v*basis[1][1] + w*basis[2][1]
        c = u*basis[0][2] + v*basis[1][2] + w*basis[2][2]
        d = u*basis[0][3] + v*basis[1][3] + w*basis[2][3]

        surf_eq = a*b**2 + b*c**2 + c*d**2 + d*a**2

        H = jacobian(jacobian(surf_eq, (u, v, w)), (u, v, w))
        flex_eq = H.determinant()

        R_bi = PolynomialRing(Fp, 'U,V')
        U, V = R_bi.gens()

        f_aff = surf_eq(u=U, v=V, w=1)
        h_aff = flex_eq(u=U, v=V, w=1)

        f_str = str(f_aff).replace("**", "^")
        h_str = str(h_aff).replace("**", "^")

        magma_script = f"""
        p := {p};
        F := GF(p);
        R<U, V> := PolynomialRing(F, 2);

        f := {f_str};
        h := {h_str};

        res_u_multi := Resultant(f, h, V);

        P<u> := PolynomialRing(F);
        coeffs := Coefficients(res_u_multi, U);
        res_u := P!0;
        for i := 1 to #coeffs do
            res_u := res_u + P!(coeffs[i]) * u^(i-1);
        end for;

        roots_u := Roots(res_u);

        found_u := -1;
        found_v := -1;

        for r in roots_u do
            u_val := r[1];

            Pv<v> := PolynomialRing(F);

            f_v := Evaluate(f, [u_val, v]);
            h_v := Evaluate(h, [u_val, v]);

            common_v := Roots(GCD(f_v, h_v));
            
            if #common_v gt 0 then
                found_u := u_val;
                found_v := common_v[1][1];
                break;
            end if;
        end for;

        if found_u ne -1 then
            print found_u;
            print found_v;
        else
            print "FAIL";
        end if;
        """

        line = magma_free(magma_script).split("\n")
        u_val = int(line[0])
        v_val = int(line[1])

        u_sol = Fp(u_val)
        v_sol = Fp(v_val)
        w_sol = Fp(1)

        # Map back to (a,b,c,d) basis
        GO = (u_sol*basis[0] + v_sol*basis[1] + w_sol*basis[2]).list()

        print(f"{p = }")
        print(f"{G0 = }")
        print(f"{GO = }")

        #io = process(["python3", "chall.py"])
        io = remote("challenge.cnsc.com.vn", "30358")
        io.sendlineafter(b"p = ", str(p).encode())
        io.sendlineafter(b"G = ", ",".join([str(c) for c in G0]).encode())
        io.sendlineafter(b"O = ", ",".join([str(c) for c in GO]).encode())
        GP = eval(io.recvline().decode().strip().split(" = ")[1])
        Fp = GF(p)
        GP = [Fp(c) for c in GP]
        print(f"{GP = }")
        io.close()

        L = matrix(Fp, [G0, GO, GP]).right_kernel_matrix()

        x, y, z, w = L[0]

        b, c, d = Fp["b, c, d"].gens()
        a = - (y/x) * b - (z/x) * c - (w/x) * d
        f = a * b**2 + b * c**2 + c * d**2 + d * a**2

        assert f(G0[1], G0[2], G0[3]) == 0
        assert f(GP[1], GP[2], GP[3]) == 0

        SCRIPT = f"""
        p := {str(p)};
        F := GF(p);

        P2<b,c,d> := ProjectiveSpace(F, 2);

        f := {str(f)};
        C := Curve(P2, f);

        P0  := C!{[GO[1], GO[2], GO[3]]};
        PG0 := C!{[G0[1], G0[2], G0[3]]};
        PGP := C!{[GP[1], GP[2], GP[3]]};

        E, psi := EllipticCurve(C, P0);

        print E;

        ainv := aInvariants(E);

        print ainv[1];
        print ainv[2];
        print ainv[3];
        print ainv[4];
        print ainv[5];

        QG0 := psi(PG0);
        QGP := psi(PGP);
        print QG0;
        print QGP;
        """

        line = str(magma_free(SCRIPT)).split("\n")

        a = [int(line[i]) for i in range(1, 6)]
        E = EllipticCurve(GF(p), a)
        print(E)

        QG0_str = line[6].strip()
        QGP_str = line[7].strip()

        def parse_proj_point(s):
            s = s.strip("() ")
            xs, ys, zs = [t.strip() for t in s.split(":")]
            return (Fp(xs), Fp(ys), Fp(zs))

        X0,Y0,Z0 = parse_proj_point(QG0_str)
        XP,YP,ZP = parse_proj_point(QGP_str)

        if Z0 == 0:
            EG = E(0)
        else:
            EG = E(X0/Z0, Y0/Z0)

        if ZP == 0:
            EP = E(0)
        else:
            EP = E(XP/ZP, YP/ZP)

        primes = []
        dlogs = []

        for pp, i in factor(EG.order(), limit=2**25)[:-1]:
            primes.append(pp)


        EGo = int(EG.order())

        def bsgs(G, P, fac):
            N = ceil(sqrt(fac))
            tbl = {i * G: i for i in range(N)}
            C = - (N * G) 
            
            for j in range(N): 
                y = j * C + P
                if y in tbl:
                    return j * N + tbl[y]
            
        for fac in primes:
            t = EGo // fac
            dlog = bsgs(t*EG, t*EP, fac)
            dlogs += [dlog]
            print("factor:", str(fac), "done")

        print(primes)
        print(dlogs)
        rs += dlogs
        ms += primes
        
        if LCM(ms).bit_length() > 255:
            break
    except:
        continue

print(long_to_bytes(int(crt(rs, ms))))
