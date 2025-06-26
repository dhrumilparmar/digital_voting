const SHA256 = require('crypto-js/sha256');

class Block {
    constructor(timestamp, voteData, previousHash = '') {
        this.timestamp = timestamp;
        this.voteData = voteData;
        this.previousHash = previousHash;
        this.hash = this.calculateHash();
        this.nonce = 0;
    }

    calculateHash() {
        return SHA256(
            this.previousHash + 
            this.timestamp + 
            JSON.stringify(this.voteData) + 
            this.nonce
        ).toString();
    }

    mineBlock(difficulty) {
        while (this.hash.substring(0, difficulty) !== Array(difficulty + 1).join("0")) {
            this.nonce++;
            this.hash = this.calculateHash();
        }
        console.log("Block mined: " + this.hash);
    }
}

class VoteChain {
    constructor() {
        this.chain = [this.createGenesisBlock()];
        this.difficulty = 2;
        this.pendingVotes = [];
    }

    createGenesisBlock() {
        return new Block(Date.now(), { message: "Genesis Block" }, "0");
    }

    getLatestBlock() {
        return this.chain[this.chain.length - 1];
    }

    addVote(voterID, candidateName) {
        const voteData = {
            voterID: SHA256(voterID).toString(),
            candidateName: candidateName,
            timestamp: Date.now()
        };
        this.pendingVotes.push(voteData);
        return this.minePendingVotes();
    }

    minePendingVotes() {
        const block = new Block(
            Date.now(), 
            this.pendingVotes, 
            this.getLatestBlock().hash
        );
        block.mineBlock(this.difficulty);

        console.log('Block mined successfully!');
        this.chain.push(block);
        this.pendingVotes = [];
        return block;
    }

    isChainValid() {
        for (let i = 1; i < this.chain.length; i++) {
            const currentBlock = this.chain[i];
            const previousBlock = this.chain[i - 1];

            if (currentBlock.hash !== currentBlock.calculateHash()) {
                return false;
            }

            if (currentBlock.previousHash !== previousBlock.hash) {
                return false;
            }
        }
        return true;
    }

    getVoteCount() {
        const voteCounts = {};
        
        for (const block of this.chain) {
            if (Array.isArray(block.voteData)) {
                for (const vote of block.voteData) {
                    if (vote.candidateName) {
                        voteCounts[vote.candidateName] = (voteCounts[vote.candidateName] || 0) + 1;
                    }
                }
            }
        }
        return voteCounts;
    }
}

module.exports = { VoteChain, Block };