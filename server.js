import express from 'express';
import dotenv from 'dotenv';
import bcrypt from 'bcryptjs';
import Database from 'better-sqlite3';
import midtransClient from 'midtrans-client';
import crypto from 'crypto';
import path from 'path';
import { fileURLToPath } from 'url';

dotenv.config();

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();

/* =========================================================
   BASIC CONFIG
========================================================= */

const PORT = Number(process.env.PORT || 3000);
const SESSION_DAYS = 30;
const CODE_RESERVATION_MINUTES = 15;

app.disable('x-powered-by');

app.use(
  express.json({
    limit: '1mb'
  })
);

app.use(
  express.urlencoded({
    extended: false,
    limit: '1mb'
  })
);

app.use(
  express.static(
    path.join(__dirname, 'public')
  )
);

// Serve the actual app entry files from the project root when the
// frontend is not stored in a separate public/ directory.
app.use(
  express.static(__dirname)
);


/* =========================================================
   DATABASE
========================================================= */

const db = new Database(
  path.join(__dirname, 'data.db')
);
