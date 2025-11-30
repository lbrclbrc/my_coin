# merkle_tree.py


from wrappers.poseidon_hash_wrapper import get_poseidon_hash


class MerkleTree:
    ZERO_LEAF = "0" * 64

    def __init__(self):
        self.leaves = []
        self.levels = []
        self._rebuild()

    def _norm_hex(self, s):
        # Strip whitespace without modifying format
        if not isinstance(s, str):
            s = str(s)
        return s.strip()

    def _h2(self, left_hex, right_hex):
        # Poseidon hash using raw-bytes semantics for 32-byte hex strings
        return get_poseidon_hash(left_hex, right_hex)

    def _rebuild(self):
        base = []
        for x in self.leaves:
            base.append(self._norm_hex(x))

        self.levels = [base]

        if len(base) == 0:
            return

        cur = base
        while len(cur) > 1:
            if len(cur) % 2 == 1:
                cur = cur + [self.ZERO_LEAF]
            nxt = []
            i = 0
            while i < len(cur):
                left = cur[i]
                right = cur[i + 1]
                parent = self._h2(left, right)
                nxt.append(parent)
                i += 2
            self.levels.append(nxt)
            cur = nxt

    def append(self, leaf_hex):
        self.leaves.append(self._norm_hex(leaf_hex))
        self._rebuild()

    def update(self, index, leaf_hex):
        self.leaves[index] = self._norm_hex(leaf_hex)
        self._rebuild()

    def root(self):
        if len(self.levels) == 0:
            return self.ZERO_LEAF
        if len(self.levels[0]) == 0:
            return self.ZERO_LEAF
        return self.levels[-1][0]

    def gen_proof(self, index):
        """
        Return ordered proof:
          [ (sibling_hex, "L"/"R"), ... ]
        "L" means sibling is on the left.
        "R" means sibling is on the right.

        If the sibling does not exist in a layer
        (for example when the layer has odd count),
        ZERO_LEAF is used as the sibling to keep semantics consistent
        with padding used during tree construction.
        """
        proof = []
        idx = index
        h = 0

        while h < len(self.levels) - 1:
            layer = self.levels[h]
            if len(layer) <= 1:
                break

            if idx % 2 == 0:
                sib = idx + 1
                direction = "R"
            else:
                sib = idx - 1
                direction = "L"

            if sib < 0 or sib >= len(layer):
                sib_hex = self.ZERO_LEAF
            else:
                sib_hex = layer[sib]

            proof.append((sib_hex, direction))
            idx = idx // 2
            h += 1

        return proof

    def size(self):
        return len(self.leaves)


class MerkleTreeCommit(MerkleTree):
    DEPTH = 32

    def __init__(self):
        super().__init__()

    def _rebuild(self):
        # First build shallow layers using parent class
        super()._rebuild()

        if len(self.leaves) == 0:
            return

        cur = [self.levels[-1][0]]

        # Extend levels to fixed depth using ZERO_LEAF padding
        while len(self.levels) - 1 < self.DEPTH:
            parent = self._h2(cur[0], self.ZERO_LEAF)
            cur = [parent]
            self.levels.append(cur)

    def gen_proof(self, index):
        """
        Return ordered proof with fixed depth DEPTH.
        Sibling is ZERO_LEAF when the layer does not exist
        or the sibling is out of range.
        """
        proof = []
        idx = index
        h = 0

        while h < self.DEPTH:
            if h < len(self.levels) - 1:
                layer = self.levels[h]

                if idx % 2 == 0:
                    sib = idx + 1
                    direction = "R"
                    if sib < len(layer):
                        sib_hex = layer[sib]
                    else:
                        sib_hex = self.ZERO_LEAF
                else:
                    sib = idx - 1
                    direction = "L"
                    if sib >= 0 and sib < len(layer):
                        sib_hex = layer[sib]
                    else:
                        sib_hex = self.ZERO_LEAF
            else:
                sib_hex = self.ZERO_LEAF
                if idx % 2 == 0:
                    direction = "R"
                else:
                    direction = "L"

            proof.append((sib_hex, direction))
            idx = idx // 2
            h += 1

        return proof
