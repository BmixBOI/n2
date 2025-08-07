// database.js
const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');
const helmet = require('helmet');
class DatabaseManager {
    constructor() {
        this.accounts = new Map();
        this.messages = new Map();
        this.userBlocks = new Map(); // Add userBlocks property
        this.dataFile = path.join(__dirname, '..', 'data', 'accounts.json');
        this.backupInterval = 5 * 60 * 1000; // 5 minutes
        this.backupTimer = null;
    }

    async init() {
        try {
            // Ensure data directory exists
            const dataDir = path.dirname(this.dataFile);
            try {
                await fs.access(dataDir);
            } catch (error) {
                await fs.mkdir(dataDir, { recursive: true });
                console.log(`[${new Date().toISOString()}] Created data directory: ${dataDir}`);
            }

            // Load existing accounts
            await this.loadAccounts();
            
            // Start automated backups
            this.startBackupTimer();
            
            console.log(`[${new Date().toISOString()}] DataManager initialized with ${this.accounts.size} accounts`);
        } catch (error) {
            console.error('Failed to initialize DataManager:', error);
            throw error;
        }
    }

    async loadAccounts() {
        try {
            await fs.access(this.dataFile);
            const data = await fs.readFile(this.dataFile, 'utf8');
            const accountsData = JSON.parse(data);
            
            // Convert back to Map
            this.accounts.clear();
            for (const [id, account] of Object.entries(accountsData)) {
                this.accounts.set(id, {
                    ...account,
                    createdAt: new Date(account.createdAt),
                    lastLogin: account.lastLogin ? new Date(account.lastLogin) : null
                });
            }
            
            console.log(`[${new Date().toISOString()}] Loaded ${this.accounts.size} accounts from storage`);
        } catch (error) {
            if (error.code === 'ENOENT') {
                console.log(`[${new Date().toISOString()}] No existing accounts file found, starting fresh`);
            } else {
                console.error('Error loading accounts:', error);
                throw error;
            }
        }
    }

    async saveAccounts() {
        try {
            // Convert Map to Object for JSON storage
            const accountsData = Object.fromEntries(this.accounts);
            
            // Create backup of current file if it exists
            try {
                await fs.access(this.dataFile);
                const backupFile = this.dataFile + `.backup.${Date.now()}`;
                await fs.copyFile(this.dataFile, backupFile);
                
                // Keep only last 5 backups
                await this.cleanupOldBackups();
            } catch (error) {
                // File doesn't exist yet, no backup needed
            }
            
            // Write new data
            await fs.writeFile(this.dataFile, JSON.stringify(accountsData, null, 2));
            console.log(`[${new Date().toISOString()}] Saved ${this.accounts.size} accounts to storage`);
        } catch (error) {
            console.error('Error saving accounts:', error);
            throw error;
        }
    }

    async cleanupOldBackups() {
        try {
            const dataDir = path.dirname(this.dataFile);
            const files = await fs.readdir(dataDir);
            const backupFiles = files
                .filter(file => file.startsWith('accounts.json.backup.'))
                .map(file => ({
                    name: file,
                    path: path.join(dataDir, file),
                    timestamp: parseInt(file.split('.').pop())
                }))
                .sort((a, b) => b.timestamp - a.timestamp);

            // Keep only the 5 most recent backups
            const filesToDelete = backupFiles.slice(5);
            for (const file of filesToDelete) {
                await fs.unlink(file.path);
                console.log(`[${new Date().toISOString()}] Deleted old backup: ${file.name}`);
            }
        } catch (error) {
            console.error('Error cleaning up backups:', error);
        }
    }

    async setAccount(id, account) {
        try {
            this.accounts.set(id, {
                ...account,
                createdAt: new Date(account.createdAt),
                lastLogin: account.lastLogin ? new Date(account.lastLogin) : null
            });
            await this.saveAccounts();
            return true;
        } catch (error) {
            console.error('Error setting account:', error);
            throw error;
        }
    }

    getAccount(id) {
        return this.accounts.get(id);
    }

    deleteAccount(id) {
        const deleted = this.accounts.delete(id);
        if (deleted) {
            this.debouncedSave();
        }
        return deleted;
    }

    getAllAccounts() {
        return Array.from(this.accounts.values());
    }

    getAccountsCount() {
        return this.accounts.size;
    }

    // Debounced save to avoid too frequent writes
    debouncedSave() {
        if (this.saveTimer) {
            clearTimeout(this.saveTimer);
        }
        this.saveTimer = setTimeout(() => {
            this.saveAccounts().catch(error => {
                console.error('Error in debounced save:', error);
            });
        }, 1000); // Save 1 second after last modification
    }

    startBackupTimer() {
        if (this.backupTimer) {
            clearInterval(this.backupTimer);
        }
        
        this.backupTimer = setInterval(() => {
            this.saveAccounts().catch(error => {
                console.error('Error in scheduled backup:', error);
            });
        }, this.backupInterval);
    }

    stopBackupTimer() {
        if (this.backupTimer) {
            clearInterval(this.backupTimer);
            this.backupTimer = null;
        }
    }

    // Create a full backup with timestamp
    async createFullBackup() {
        try {
            const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
            const backupFile = this.dataFile.replace('.json', `_full_backup_${timestamp}.json`);
            
            const accountsData = Object.fromEntries(this.accounts);
            await fs.writeFile(backupFile, JSON.stringify(accountsData, null, 2));
            
            console.log(`[${new Date().toISOString()}] Created full backup: ${backupFile}`);
            return backupFile;
        } catch (error) {
            console.error('Error creating full backup:', error);
            throw error;
        }
    }

    // Get statistics about the data
    getStats() {
        const accounts = Array.from(this.accounts.values());
        const now = new Date();
        const oneDayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);
        const oneWeekAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);

        return {
            totalAccounts: accounts.length,
            newAccountsToday: accounts.filter(acc => acc.createdAt > oneDayAgo).length,
            newAccountsThisWeek: accounts.filter(acc => acc.createdAt > oneWeekAgo).length,
            activeToday: accounts.filter(acc => acc.lastLogin && acc.lastLogin > oneDayAgo).length,
            activeThisWeek: accounts.filter(acc => acc.lastLogin && acc.lastLogin > oneWeekAgo).length,
            suspendedAccounts: accounts.filter(acc => acc.suspended).length,
            oldestAccount: accounts.reduce((oldest, acc) => 
                !oldest || acc.createdAt < oldest.createdAt ? acc : oldest, null),
            newestAccount: accounts.reduce((newest, acc) => 
                !newest || acc.createdAt > newest.createdAt ? acc : newest, null)
        };
    }

    // Search accounts by username or email
    searchAccounts(query) {
        const searchTerm = query.toLowerCase();
        return Array.from(this.accounts.values()).filter(account => 
            account.username.toLowerCase().includes(searchTerm) ||
            (account.email && account.email.toLowerCase().includes(searchTerm))
        );
    }

    async getAccountByUsername(username) {
        try {
            const accounts = Array.from(this.accounts.values());
            const account = accounts.find(acc => 
                acc.username.toLowerCase() === username.toLowerCase()
            );
            return account || null;
        } catch (error) {
            console.error('Error getting account by username:', error);
            throw error;
        }
    }

    async updateLastLogin(userId) {
        try {
            const account = this.accounts.get(userId);
            if (account) {
                account.lastLogin = new Date();
                await this.saveAccounts();
            }
            return true;
        } catch (error) {
            console.error('Error updating last login:', error);
            throw error;
        }
    }

    async getMessages(chatType, chatId) {
        try {
            const chatKey = `${chatType}_${chatId}`;
            const messages = this.messages.get(chatKey) || [];
            return messages.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
        } catch (error) {
            console.error('Error getting messages:', error);
            throw error;
        }
    }

    async saveMessage(message) {
        try {
            const chatKey = `${message.chatType}_${message.chatId}`;
            if (!this.messages.has(chatKey)) {
                this.messages.set(chatKey, []);
            }
            const chatMessages = this.messages.get(chatKey);
            chatMessages.push({
                ...message,
                timestamp: new Date(message.timestamp)
            });
            this.messages.set(chatKey, chatMessages);
            return true;
        } catch (error) {
            console.error('Error saving message:', error);
            throw error;
        }
    }

    async deleteMessage(messageId, chatType, chatId) {
        try {
            const chatKey = `${chatType}_${chatId}`;
            const messages = this.messages.get(chatKey) || [];
            const index = messages.findIndex(msg => msg.id === messageId);
            if (index !== -1) {
                messages.splice(index, 1);
                this.messages.set(chatKey, messages);
                return true;
            }
            return false;
        } catch (error) {
            console.error('Error deleting message:', error);
            throw error;
        }
    }

    async getBlockedUsers(userId) {
        try {
            const blockedUsers = this.userBlocks.get(userId) || new Set();
            return Array.from(blockedUsers).map(blockedId => ({
                id: blockedId,
                ...this.accounts.get(blockedId)
            })).filter(user => user.id); // Filter out any invalid users
        } catch (error) {
            console.error('Error getting blocked users:', error);
            return [];
        }
    }

    async blockUser(userId, blockedUserId) {
        try {
            if (!this.userBlocks.has(userId)) {
                this.userBlocks.set(userId, new Set());
            }
            this.userBlocks.get(userId).add(blockedUserId);
            await this.saveData();
            return true;
        } catch (error) {
            console.error('Error blocking user:', error);
            throw error;
        }
    }

    async unblockUser(userId, blockedUserId) {
        try {
            const userBlockSet = this.userBlocks.get(userId);
            if (userBlockSet) {
                userBlockSet.delete(blockedUserId);
                await this.saveData();
            }
            return true;
        } catch (error) {
            console.error('Error unblocking user:', error);
            throw error;
        }
    }

    async saveData() {
        try {
            const data = {
                accounts: Object.fromEntries(this.accounts),
                messages: Object.fromEntries(this.messages),
                userBlocks: Object.fromEntries(this.userBlocks) // Add userBlocks to saved data
            };
            await fs.writeFile(this.dataFile, JSON.stringify(data, null, 2));
        } catch (error) {
            console.error('Error saving data:', error);
            throw error;
        }
    }

    async loadData() {
        try {
            const data = JSON.parse(await fs.readFile(this.dataFile, 'utf8'));
            this.accounts = new Map(Object.entries(data.accounts || {}));
            this.messages = new Map(Object.entries(data.messages || {}));
            this.userBlocks = new Map(Object.entries(data.userBlocks || {})); // Load userBlocks
        } catch (error) {
            if (error.code === 'ENOENT') {
                console.log('No existing data file found, starting fresh');
            } else {
                throw error;
            }
        }
    }

    // Graceful shutdown
    async shutdown() {
        console.log(`[${new Date().toISOString()}] DataManager shutting down...`);
        
        // Stop backup timer
        this.stopBackupTimer();
        
        // Clear save timer
        if (this.saveTimer) {
            clearTimeout(this.saveTimer);
        }
        
        // Final save
        await this.saveAccounts();
        
        // Create final backup
        await this.createFullBackup();
        
        console.log(`[${new Date().toISOString()}] DataManager shutdown complete`);
    }
}

// Export the class itself
module.exports = { DatabaseManager };