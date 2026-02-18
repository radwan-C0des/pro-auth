import { pgTable, serial, text, boolean, timestamp, integer } from "drizzle-orm/pg-core";

export const users = pgTable('users', {
    id: serial("id").primaryKey(),
    email: text("email").notNull().unique(),
    name: text("name").notNull(),  
    password: text("password").notNull(),  
    isEmailVerified: boolean("is_email_verified").default(false),
    emailVerifyToken: text("email_verify_token"),
    emailVerifyExpires: timestamp("email_verify_expires"),
    passwordResetToken: text("password_reset_token"),
    passwordResetExpires: timestamp("password_reset_expires"),
    isActive: boolean("is_active").default(true),
    createdAt: timestamp("created_at").defaultNow().notNull(),
    updatedAt: timestamp("updated_at").defaultNow().notNull().$onUpdate(() => new Date())
});

export const refreshTokens = pgTable('refresh_tokens', {
    id: serial("id").primaryKey(),
    userId: integer("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),  
    token: text("token").unique().notNull(),
    expiresAt: timestamp("expires_at").notNull(),
    isRevoked: boolean("is_revoked").default(false),
    createdAt: timestamp("created_at").defaultNow().notNull()
});

export const auditLogs = pgTable("audit_logs", {  
    id: serial("id").primaryKey(),
    userId: integer("user_id").references(() => users.id, { onDelete: "set null" }),  
    action: text("action").notNull(),
    ipAddress: text("ip_address").notNull(),
    userAgent: text("user_agent").notNull(),
    success: boolean("success").default(true).notNull(),
    metadata: text("metadata"),
    createdAt: timestamp("created_at").defaultNow().notNull()
});