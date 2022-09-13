use crate::common::errors::{CryptoError, Result};

const W: u64 = 64;
const N: usize = 312;
const M: usize = 156;
// const R: u64 = 31;
const A: u64 = 0xb5026f5aa96619e9;
const U: u64 = 29;
const D: u64 = 0x5555555555555555;
const S: u64 = 17;
const B: u64 = 0x71d67fffeda60000;
const T: u64 = 37;
const C: u64 = 0xfff7eee000000000;
const L: u64 = 43;
const F: u64 = 6364136223846793005;
// const LOWER_MASK: u64 = (1 << R) - 1;
// const UPPER_MASK: u64 = (!LOWER_MASK as u64) as u64;
const LOWER_MASK: u64 = 0xFFFFFFFF80000000;
const UPPER_MASK: u64 = 0x7FFFFFFF;

pub struct Mt19937_64 {
    mt: [u64; N],
    index: usize,
}

impl Mt19937_64 {
    pub fn new() -> Self {
        let mut new = Mt19937_64 {
            mt: [0u64; N],
            index: N as usize + 1,
        };
        new.seed_mt(5489);
        new
    }

    pub fn seeded(seed: u64) -> Self {
        let mut new = Mt19937_64 {
            mt: [0u64; N],
            index: N as usize + 1,
        };
        new.seed_mt(seed);
        new
    }

    pub fn seed_mt(self: &mut Self, seed: u64) {
        self.index = N;
        self.mt[0] = seed as u64;

        (1..N).for_each(|i| {
            self.mt[i] = F.wrapping_mul(self.mt[i - 1] ^ self.mt[i - 1] >> (W - 2)) + i as u64
        })
    }

    fn twist(self: &mut Self) {
        (0..N - 1).for_each(|i| {
            if i < 5 {print!("{i}: ")};
            let x = (self.mt[i] & UPPER_MASK) | ((self.mt[(i + 1) % N]) & LOWER_MASK);
            if i < 5 {print!("x: {x} ")};
            let x_a = if x % 2 == 0 { x >> 1 } else { (x >> 1) ^ A };
            self.mt[i] = self.mt[(i + M) % N] ^ x_a;
            if i < 5 {print!("mt[i]: {}\n", self.mt[i])};
        });
        self.index = 0;
    }

    pub fn extract_number(self: &mut Self) -> Result<u64> {
        if self.index >= N {
            if self.index > N {
                return Err(CryptoError::MersenneTwisterNotSeededError);
            }
            self.twist()
        }
        let mut y: u64 = self.mt[self.index];
        y ^= (y >> U) & D;
        y ^= (y << S) & B;
        y ^= (y << T) & C;
        y ^= y >> L;
        self.index += 1;
        Ok(y as u64)
    }
}

#[cfg(test)]
mod test_mersenne_twister {
    use super::*;
    use crate::common::expectations::*;

    #[test]
    fn test_seed() {
        let mut gen_64 = Mt19937_64::new();

        expect_eq(5489, gen_64.mt[0], "").unwrap();
        expect_eq(13057201162865595358, gen_64.mt[1], "").unwrap();
        expect_eq(10476979627314799022, gen_64.mt[2], "").unwrap();
        expect_eq(15076282145854160703, gen_64.mt[3], "").unwrap();
        expect_eq(4028258760921719184, gen_64.mt[4], "").unwrap();
        expect_eq(16400131027729929813, gen_64.mt[5], "").unwrap();
        expect_eq(681049467949274916, gen_64.mt[6], "").unwrap();
        expect_eq(1166424544479915355, gen_64.mt[7], "").unwrap();
        expect_eq(12669671669325274631, gen_64.mt[8], "").unwrap();
        expect_eq(3923681680445358570, gen_64.mt[9], "").unwrap();
        expect_eq(10843524099671305260, gen_64.mt[10], "").unwrap();
        expect_eq(9320087349666649633, gen_64.mt[11], "").unwrap();
        expect_eq(18036750184230437171, gen_64.mt[12], "").unwrap();
        expect_eq(15162073532206564733, gen_64.mt[13], "").unwrap();
        expect_eq(6406996757156837684, gen_64.mt[14], "").unwrap();
        expect_eq(8927855092125653344, gen_64.mt[15], "").unwrap();
        expect_eq(7287101680298317085, gen_64.mt[16], "").unwrap();
        expect_eq(14285962336228661757, gen_64.mt[17], "").unwrap();
        expect_eq(16767098162355983288, gen_64.mt[18], "").unwrap();
        expect_eq(3083970833968823538, gen_64.mt[19], "").unwrap();
        expect_eq(16292429955202811038, gen_64.mt[20], "").unwrap();
        expect_eq(2462140788281684654, gen_64.mt[21], "").unwrap();
        expect_eq(14987206012938009260, gen_64.mt[22], "").unwrap();
        expect_eq(1755961132248244698, gen_64.mt[23], "").unwrap();
        expect_eq(11853308388629125482, gen_64.mt[24], "").unwrap();
        expect_eq(15567715879394119521, gen_64.mt[25], "").unwrap();
        expect_eq(12922380697022943828, gen_64.mt[26], "").unwrap();
        expect_eq(10568493380422968121, gen_64.mt[27], "").unwrap();
        expect_eq(6468114481096881787, gen_64.mt[28], "").unwrap();
        expect_eq(6912714088192792975, gen_64.mt[29], "").unwrap();
        expect_eq(11676810063224680468, gen_64.mt[30], "").unwrap();
        expect_eq(7989628851951361533, gen_64.mt[31], "").unwrap();
        expect_eq(9980521080467753324, gen_64.mt[32], "").unwrap();
        expect_eq(11628798235400288887, gen_64.mt[33], "").unwrap();
        expect_eq(3042835494701912499, gen_64.mt[34], "").unwrap();
        expect_eq(10149139922063010202, gen_64.mt[35], "").unwrap();
        expect_eq(258211445411067868, gen_64.mt[36], "").unwrap();
        expect_eq(12292608484108957137, gen_64.mt[37], "").unwrap();
        expect_eq(5167437948048335677, gen_64.mt[38], "").unwrap();
        expect_eq(11526653342107776435, gen_64.mt[39], "").unwrap();
        expect_eq(9186605994989076293, gen_64.mt[40], "").unwrap();
        expect_eq(4106436007230823197, gen_64.mt[41], "").unwrap();
        expect_eq(1482400223179564867, gen_64.mt[42], "").unwrap();
        expect_eq(18329651462931014642, gen_64.mt[43], "").unwrap();
        expect_eq(12828698185960104073, gen_64.mt[44], "").unwrap();
        expect_eq(9435381729478913436, gen_64.mt[45], "").unwrap();
        expect_eq(10988179007923054324, gen_64.mt[46], "").unwrap();
        expect_eq(16279301207772373869, gen_64.mt[47], "").unwrap();
        expect_eq(213769070704315526, gen_64.mt[48], "").unwrap();
        expect_eq(2960748844084063679, gen_64.mt[49], "").unwrap();
        expect_eq(10067976150718286789, gen_64.mt[50], "").unwrap();
        expect_eq(9138367034755369774, gen_64.mt[51], "").unwrap();
        expect_eq(13806268603918059639, gen_64.mt[52], "").unwrap();
        expect_eq(1680185388186896326, gen_64.mt[53], "").unwrap();
        expect_eq(10291061633078204420, gen_64.mt[54], "").unwrap();
        expect_eq(14465151537550734149, gen_64.mt[55], "").unwrap();
        expect_eq(15488623881140223366, gen_64.mt[56], "").unwrap();
        expect_eq(3741484074564668314, gen_64.mt[57], "").unwrap();
        expect_eq(1918677755306815564, gen_64.mt[58], "").unwrap();
        expect_eq(7317293401479426455, gen_64.mt[59], "").unwrap();
        expect_eq(4481774452245242266, gen_64.mt[60], "").unwrap();
        expect_eq(13177439052661313103, gen_64.mt[61], "").unwrap();
        expect_eq(14190197572724422343, gen_64.mt[62], "").unwrap();
        expect_eq(11391962132027874483, gen_64.mt[63], "").unwrap();
        expect_eq(14461854875984255581, gen_64.mt[64], "").unwrap();
        expect_eq(78864998355633351, gen_64.mt[65], "").unwrap();
        expect_eq(13375647221931413565, gen_64.mt[66], "").unwrap();
        expect_eq(13091373515385904214, gen_64.mt[67], "").unwrap();
        expect_eq(6049165922138400520, gen_64.mt[68], "").unwrap();
        expect_eq(11416142809731847130, gen_64.mt[69], "").unwrap();
        expect_eq(18197073924412990782, gen_64.mt[70], "").unwrap();
        expect_eq(829354708239552256, gen_64.mt[71], "").unwrap();
        expect_eq(7594476051345711944, gen_64.mt[72], "").unwrap();
        expect_eq(10772269459197422366, gen_64.mt[73], "").unwrap();
        expect_eq(9316238444709656630, gen_64.mt[74], "").unwrap();
        expect_eq(820820292010192239, gen_64.mt[75], "").unwrap();
        expect_eq(10370107716384591311, gen_64.mt[76], "").unwrap();
        expect_eq(8321593491012460630, gen_64.mt[77], "").unwrap();
        expect_eq(9226632414975219865, gen_64.mt[78], "").unwrap();
        expect_eq(1121855342335555726, gen_64.mt[79], "").unwrap();
        expect_eq(2523212579397444422, gen_64.mt[80], "").unwrap();
        expect_eq(15150453816516406687, gen_64.mt[81], "").unwrap();
        expect_eq(4357348246254069950, gen_64.mt[82], "").unwrap();
        expect_eq(1475811360713763769, gen_64.mt[83], "").unwrap();
        expect_eq(14612290868631353049, gen_64.mt[84], "").unwrap();
        expect_eq(13002835200640305831, gen_64.mt[85], "").unwrap();
        expect_eq(8841644283678816855, gen_64.mt[86], "").unwrap();
        expect_eq(9422668006636366709, gen_64.mt[87], "").unwrap();
        expect_eq(9762262470164229443, gen_64.mt[88], "").unwrap();
        expect_eq(15759907042128835526, gen_64.mt[89], "").unwrap();
        expect_eq(5472764997485778171, gen_64.mt[90], "").unwrap();
        expect_eq(7662827925729932877, gen_64.mt[91], "").unwrap();
        expect_eq(17501417670658457528, gen_64.mt[92], "").unwrap();
        expect_eq(3930325588003666236, gen_64.mt[93], "").unwrap();
        expect_eq(5474808447603626986, gen_64.mt[94], "").unwrap();
        expect_eq(6720003803709822382, gen_64.mt[95], "").unwrap();
        expect_eq(1855653125818638627, gen_64.mt[96], "").unwrap();
        expect_eq(17923060195536629896, gen_64.mt[97], "").unwrap();
        expect_eq(1006421872699162065, gen_64.mt[98], "").unwrap();
        expect_eq(8593337867538992416, gen_64.mt[99], "").unwrap();
        expect_eq(4799988366622961201, gen_64.mt[100], "").unwrap();
        expect_eq(13724225912419217109, gen_64.mt[101], "").unwrap();
        expect_eq(11153468036382729521, gen_64.mt[102], "").unwrap();
        expect_eq(3227521569234212702, gen_64.mt[103], "").unwrap();
        expect_eq(14253271084513918446, gen_64.mt[104], "").unwrap();
        expect_eq(12720552637491820050, gen_64.mt[105], "").unwrap();
        expect_eq(3131078640163418426, gen_64.mt[106], "").unwrap();
        expect_eq(13204035025191316893, gen_64.mt[107], "").unwrap();
        expect_eq(1242013424098797151, gen_64.mt[108], "").unwrap();
        expect_eq(10309732291143311392, gen_64.mt[109], "").unwrap();
        expect_eq(14812467554029601896, gen_64.mt[110], "").unwrap();
        expect_eq(6588807180369779774, gen_64.mt[111], "").unwrap();
        expect_eq(15873501535677970563, gen_64.mt[112], "").unwrap();
        expect_eq(11172284785033359089, gen_64.mt[113], "").unwrap();
        expect_eq(12301618027847470633, gen_64.mt[114], "").unwrap();
        expect_eq(11068608208873034498, gen_64.mt[115], "").unwrap();
        expect_eq(11428326129399486324, gen_64.mt[116], "").unwrap();
        expect_eq(5094087545013561907, gen_64.mt[117], "").unwrap();
        expect_eq(500288200114796864, gen_64.mt[118], "").unwrap();
        expect_eq(2634392864069587127, gen_64.mt[119], "").unwrap();
        expect_eq(10024792545775434147, gen_64.mt[120], "").unwrap();
        expect_eq(10356221529759776966, gen_64.mt[121], "").unwrap();
        expect_eq(11136380342514802414, gen_64.mt[122], "").unwrap();
        expect_eq(340782545860183031, gen_64.mt[123], "").unwrap();
        expect_eq(7508198866667469799, gen_64.mt[124], "").unwrap();
        expect_eq(7289875136835936747, gen_64.mt[125], "").unwrap();
        expect_eq(17690097813874199712, gen_64.mt[126], "").unwrap();
        expect_eq(2626238110689777190, gen_64.mt[127], "").unwrap();
        expect_eq(16717695660713672494, gen_64.mt[128], "").unwrap();
        expect_eq(3595834123325255274, gen_64.mt[129], "").unwrap();
        expect_eq(6135238878624366372, gen_64.mt[130], "").unwrap();
        expect_eq(9938504311934907652, gen_64.mt[131], "").unwrap();
        expect_eq(11347072173565906066, gen_64.mt[132], "").unwrap();
        expect_eq(9372835856550536661, gen_64.mt[133], "").unwrap();
        expect_eq(2901728271276724305, gen_64.mt[134], "").unwrap();
        expect_eq(9858149244111900100, gen_64.mt[135], "").unwrap();
        expect_eq(16544617798517122646, gen_64.mt[136], "").unwrap();
        expect_eq(11622889926249457786, gen_64.mt[137], "").unwrap();
        expect_eq(9979924837559772578, gen_64.mt[138], "").unwrap();
        expect_eq(14196945190861012395, gen_64.mt[139], "").unwrap();
        expect_eq(2223272152803307284, gen_64.mt[140], "").unwrap();
        expect_eq(5190516807419032337, gen_64.mt[141], "").unwrap();
        expect_eq(3235768569839659614, gen_64.mt[142], "").unwrap();
        expect_eq(7682633656132343061, gen_64.mt[143], "").unwrap();
        expect_eq(13733309948923027732, gen_64.mt[144], "").unwrap();
        expect_eq(16911272487285603183, gen_64.mt[145], "").unwrap();
        expect_eq(16702635121049437838, gen_64.mt[146], "").unwrap();
        expect_eq(6161415984776321628, gen_64.mt[147], "").unwrap();
        expect_eq(12717629078983493101, gen_64.mt[148], "").unwrap();
        expect_eq(2358424909955325080, gen_64.mt[149], "").unwrap();
        expect_eq(12297813174132617038, gen_64.mt[150], "").unwrap();
        expect_eq(9911119942162973939, gen_64.mt[151], "").unwrap();
        expect_eq(14656296979938373109, gen_64.mt[152], "").unwrap();
        expect_eq(5179190586448371415, gen_64.mt[153], "").unwrap();
        expect_eq(11090893096306857528, gen_64.mt[154], "").unwrap();
        expect_eq(11656051587341971149, gen_64.mt[155], "").unwrap();
        expect_eq(2619718836853156863, gen_64.mt[156], "").unwrap();
        expect_eq(167424595420134768, gen_64.mt[157], "").unwrap();
        expect_eq(1643007456521706830, gen_64.mt[158], "").unwrap();
        expect_eq(4530990928200931669, gen_64.mt[159], "").unwrap();
        expect_eq(4691242637059006353, gen_64.mt[160], "").unwrap();
        expect_eq(3245172607167855857, gen_64.mt[161], "").unwrap();
        expect_eq(3826074447196161535, gen_64.mt[162], "").unwrap();
        expect_eq(3017613396914933622, gen_64.mt[163], "").unwrap();
        expect_eq(17340905364626031202, gen_64.mt[164], "").unwrap();
        expect_eq(7485046344904985266, gen_64.mt[165], "").unwrap();
        expect_eq(4965505580881047325, gen_64.mt[166], "").unwrap();
        expect_eq(7607870693563722899, gen_64.mt[167], "").unwrap();
        expect_eq(7474217805999604818, gen_64.mt[168], "").unwrap();
        expect_eq(9839820025668071488, gen_64.mt[169], "").unwrap();
        expect_eq(3904404505428916804, gen_64.mt[170], "").unwrap();
        expect_eq(9096143925090925215, gen_64.mt[171], "").unwrap();
        expect_eq(11720022622728597618, gen_64.mt[172], "").unwrap();
        expect_eq(14607455239072224349, gen_64.mt[173], "").unwrap();
        expect_eq(9652489256075507508, gen_64.mt[174], "").unwrap();
        expect_eq(16157915074085584685, gen_64.mt[175], "").unwrap();
        expect_eq(8844691517984910790, gen_64.mt[176], "").unwrap();
        expect_eq(4655454640787506604, gen_64.mt[177], "").unwrap();
        expect_eq(13027405036051698459, gen_64.mt[178], "").unwrap();
        expect_eq(7614616053181367064, gen_64.mt[179], "").unwrap();
        expect_eq(7581798355918172953, gen_64.mt[180], "").unwrap();
        expect_eq(15422484141350085613, gen_64.mt[181], "").unwrap();
        expect_eq(7273144328931681164, gen_64.mt[182], "").unwrap();
        expect_eq(4809879802957181824, gen_64.mt[183], "").unwrap();
        expect_eq(8173340538785729893, gen_64.mt[184], "").unwrap();
        expect_eq(8978995124845705037, gen_64.mt[185], "").unwrap();
        expect_eq(1098023286586191126, gen_64.mt[186], "").unwrap();
        expect_eq(3673056527006128025, gen_64.mt[187], "").unwrap();
        expect_eq(10771848665549917601, gen_64.mt[188], "").unwrap();
        expect_eq(2556126669642826596, gen_64.mt[189], "").unwrap();
        expect_eq(5853974322212222290, gen_64.mt[190], "").unwrap();
        expect_eq(4132488280061906262, gen_64.mt[191], "").unwrap();
        expect_eq(7632389934273528542, gen_64.mt[192], "").unwrap();
        expect_eq(9864709072803865332, gen_64.mt[193], "").unwrap();
        expect_eq(1026796482661462016, gen_64.mt[194], "").unwrap();
        expect_eq(1419617114693595331, gen_64.mt[195], "").unwrap();
        expect_eq(3962155586201817099, gen_64.mt[196], "").unwrap();
        expect_eq(667987996344895412, gen_64.mt[197], "").unwrap();
        expect_eq(8873514502505981802, gen_64.mt[198], "").unwrap();
        expect_eq(651162605589119894, gen_64.mt[199], "").unwrap();
        expect_eq(17797581581324995622, gen_64.mt[200], "").unwrap();
        expect_eq(15976116878184660554, gen_64.mt[201], "").unwrap();
        expect_eq(612180284401625759, gen_64.mt[202], "").unwrap();
        expect_eq(5667627227252711358, gen_64.mt[203], "").unwrap();
        expect_eq(10804568037840393823, gen_64.mt[204], "").unwrap();
        expect_eq(13480141817918853670, gen_64.mt[205], "").unwrap();
        expect_eq(1066512862997122338, gen_64.mt[206], "").unwrap();
        expect_eq(3604813770717933001, gen_64.mt[207], "").unwrap();
        expect_eq(13585907467660805157, gen_64.mt[208], "").unwrap();
        expect_eq(205740876326491308, gen_64.mt[209], "").unwrap();
        expect_eq(5991394416108877582, gen_64.mt[210], "").unwrap();
        expect_eq(14926153760506158966, gen_64.mt[211], "").unwrap();
        expect_eq(1763245647862174565, gen_64.mt[212], "").unwrap();
        expect_eq(7472896455769818262, gen_64.mt[213], "").unwrap();
        expect_eq(1880205322011031649, gen_64.mt[214], "").unwrap();
        expect_eq(4964758817614792932, gen_64.mt[215], "").unwrap();
        expect_eq(9867509509583481881, gen_64.mt[216], "").unwrap();
        expect_eq(10312058868395878040, gen_64.mt[217], "").unwrap();
        expect_eq(17252972030239322092, gen_64.mt[218], "").unwrap();
        expect_eq(2606539039210012382, gen_64.mt[219], "").unwrap();
        expect_eq(12769631308639825890, gen_64.mt[220], "").unwrap();
        expect_eq(13775140203463199549, gen_64.mt[221], "").unwrap();
        expect_eq(11099918903372708849, gen_64.mt[222], "").unwrap();
        expect_eq(13347825623771273110, gen_64.mt[223], "").unwrap();
        expect_eq(10911113188423225828, gen_64.mt[224], "").unwrap();
        expect_eq(3460604650247618639, gen_64.mt[225], "").unwrap();
        expect_eq(18367317190899220421, gen_64.mt[226], "").unwrap();
        expect_eq(8882227645936398513, gen_64.mt[227], "").unwrap();
        expect_eq(17724301884678217684, gen_64.mt[228], "").unwrap();
        expect_eq(5689627886741111472, gen_64.mt[229], "").unwrap();
        expect_eq(9758983823681554691, gen_64.mt[230], "").unwrap();
        expect_eq(4544309240290776340, gen_64.mt[231], "").unwrap();
        expect_eq(11463612010490044780, gen_64.mt[232], "").unwrap();
        expect_eq(1863376090611217215, gen_64.mt[233], "").unwrap();
        expect_eq(15532585436324660221, gen_64.mt[234], "").unwrap();
        expect_eq(2614370430655215249, gen_64.mt[235], "").unwrap();
        expect_eq(8917872921271699305, gen_64.mt[236], "").unwrap();
        expect_eq(6432650944098428469, gen_64.mt[237], "").unwrap();
        expect_eq(2156285533792683026, gen_64.mt[238], "").unwrap();
        expect_eq(16620843026246231577, gen_64.mt[239], "").unwrap();
        expect_eq(7840248012245686658, gen_64.mt[240], "").unwrap();
        expect_eq(8817762536320809464, gen_64.mt[241], "").unwrap();
        expect_eq(11411624210052135095, gen_64.mt[242], "").unwrap();
        expect_eq(14469479953922933700, gen_64.mt[243], "").unwrap();
        expect_eq(7687504684721677295, gen_64.mt[244], "").unwrap();
        expect_eq(3569379597009150923, gen_64.mt[245], "").unwrap();
        expect_eq(16298388750432321701, gen_64.mt[246], "").unwrap();
        expect_eq(3546604078275180581, gen_64.mt[247], "").unwrap();
        expect_eq(14090163417090112121, gen_64.mt[248], "").unwrap();
        expect_eq(1483598196549275243, gen_64.mt[249], "").unwrap();
        expect_eq(842296961800625865, gen_64.mt[250], "").unwrap();
        expect_eq(3395823622991339856, gen_64.mt[251], "").unwrap();
        expect_eq(2860049050133253132, gen_64.mt[252], "").unwrap();
        expect_eq(15982791582006104857, gen_64.mt[253], "").unwrap();
        expect_eq(2089985782673048208, gen_64.mt[254], "").unwrap();
        expect_eq(16970930680417346639, gen_64.mt[255], "").unwrap();
        expect_eq(5169822013739423324, gen_64.mt[256], "").unwrap();
        expect_eq(10286951961495655002, gen_64.mt[257], "").unwrap();
        expect_eq(2382826956176138874, gen_64.mt[258], "").unwrap();
        expect_eq(16598361065592133237, gen_64.mt[259], "").unwrap();
        expect_eq(17932005381186616770, gen_64.mt[260], "").unwrap();
        expect_eq(16288375750215523058, gen_64.mt[261], "").unwrap();
        expect_eq(10795004077740592227, gen_64.mt[262], "").unwrap();
        expect_eq(8767132529733815572, gen_64.mt[263], "").unwrap();
        expect_eq(56240711443019961, gen_64.mt[264], "").unwrap();
        expect_eq(16559497623279599758, gen_64.mt[265], "").unwrap();
        expect_eq(110008580074802387, gen_64.mt[266], "").unwrap();
        expect_eq(11565107589793869602, gen_64.mt[267], "").unwrap();
        expect_eq(8340806487881443756, gen_64.mt[268], "").unwrap();
        expect_eq(15870344620874033014, gen_64.mt[269], "").unwrap();
        expect_eq(11296081153908292511, gen_64.mt[270], "").unwrap();
        expect_eq(7302467602367798952, gen_64.mt[271], "").unwrap();
        expect_eq(67243528223816645, gen_64.mt[272], "").unwrap();
        expect_eq(3486356707203513778, gen_64.mt[273], "").unwrap();
        expect_eq(12062986918467299164, gen_64.mt[274], "").unwrap();
        expect_eq(819578200798056089, gen_64.mt[275], "").unwrap();
        expect_eq(18327439140423416057, gen_64.mt[276], "").unwrap();
        expect_eq(14368763774382050055, gen_64.mt[277], "").unwrap();
        expect_eq(15153510095141989578, gen_64.mt[278], "").unwrap();
        expect_eq(3341425261026301804, gen_64.mt[279], "").unwrap();
        expect_eq(773058210352526100, gen_64.mt[280], "").unwrap();
        expect_eq(8392504547028739997, gen_64.mt[281], "").unwrap();
        expect_eq(16740785353247611782, gen_64.mt[282], "").unwrap();
        expect_eq(3373348860032225916, gen_64.mt[283], "").unwrap();
        expect_eq(2701382140093875432, gen_64.mt[284], "").unwrap();
        expect_eq(6671463639189304805, gen_64.mt[285], "").unwrap();
        expect_eq(2761278783662691890, gen_64.mt[286], "").unwrap();
        expect_eq(4685122996515124713, gen_64.mt[287], "").unwrap();
        expect_eq(2654082339795866344, gen_64.mt[288], "").unwrap();
        expect_eq(11329882967399066601, gen_64.mt[289], "").unwrap();
        expect_eq(15952333297690283633, gen_64.mt[290], "").unwrap();
        expect_eq(1697237544920553773, gen_64.mt[291], "").unwrap();
        expect_eq(12370315011795239181, gen_64.mt[292], "").unwrap();
        expect_eq(12798146676828103112, gen_64.mt[293], "").unwrap();
        expect_eq(6070340910131537832, gen_64.mt[294], "").unwrap();
        expect_eq(1447608530827808988, gen_64.mt[295], "").unwrap();
        expect_eq(10598487560452381652, gen_64.mt[296], "").unwrap();
        expect_eq(9074424128904564679, gen_64.mt[297], "").unwrap();
        expect_eq(10368088978608816376, gen_64.mt[298], "").unwrap();
        expect_eq(14242160977535644445, gen_64.mt[299], "").unwrap();
        expect_eq(10536783946433683314, gen_64.mt[300], "").unwrap();
        expect_eq(9271707826703226845, gen_64.mt[301], "").unwrap();
        expect_eq(16651953013385761889, gen_64.mt[302], "").unwrap();
        expect_eq(17192290660721538153, gen_64.mt[303], "").unwrap();
        expect_eq(3817850688440651218, gen_64.mt[304], "").unwrap();
        expect_eq(12138791431534730523, gen_64.mt[305], "").unwrap();
        expect_eq(15752446791766328727, gen_64.mt[306], "").unwrap();
        expect_eq(13797089951075641399, gen_64.mt[307], "").unwrap();
        expect_eq(3884892512265821573, gen_64.mt[308], "").unwrap();
        expect_eq(13501119693269626006, gen_64.mt[309], "").unwrap();
        expect_eq(6429997517378945850, gen_64.mt[310], "").unwrap();
        expect_eq(14292992949928449942, gen_64.mt[311], "").unwrap();
    }

    #[test]
    fn test_against_cpp_std_out() {
        let mut gen_64 = Mt19937_64::new();

        expect_eq(
            14514284786278117030,
            gen_64.extract_number().unwrap(),
            "mt_64 output",
        )
        .unwrap();
        expect_eq(
            4620546740167642908,
            gen_64.extract_number().unwrap(),
            "mt_64 output",
        )
        .unwrap();
        expect_eq(
            13109570281517897720,
            gen_64.extract_number().unwrap(),
            "mt_64 output",
        )
        .unwrap();
        expect_eq(
            17462938647148434322,
            gen_64.extract_number().unwrap(),
            "mt_64 output",
        )
        .unwrap();
        expect_eq(
            355488278567739596,
            gen_64.extract_number().unwrap(),
            "mt_64 output",
        )
        .unwrap();
        expect_eq(
            7469126240319926998,
            gen_64.extract_number().unwrap(),
            "mt_64 output",
        )
        .unwrap();
        expect_eq(
            4635995468481642529,
            gen_64.extract_number().unwrap(),
            "mt_64 output",
        )
        .unwrap();
        expect_eq(
            418970542659199878,
            gen_64.extract_number().unwrap(),
            "mt_64 output",
        )
        .unwrap();
        expect_eq(
            9604170989252516556,
            gen_64.extract_number().unwrap(),
            "mt_64 output",
        )
        .unwrap();
        expect_eq(
            6358044926049913402,
            gen_64.extract_number().unwrap(),
            "mt_64 output",
        )
        .unwrap();
    }
}
