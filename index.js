import express from "express";
import { MongoClient, ObjectId } from "mongodb";
import cors from "cors";
import Stripe from "stripe";
import { createRemoteJWKSet, jwtVerify } from "jose";
import "dotenv/config";

const PORT = Number(process.env.PORT) || 5000;
const CLIENT_URL = process.env.CLIENT_URL || "http://localhost:3000";
const DB_NAME = "mentor-lagbe";

// BetterAuth runs in the Next.js app and publishes its public signing keys at
// /api/auth/jwks. The API verifies every bearer token against those keys, then
// loads the user from MongoDB so role/plan changes take effect immediately.
const AUTH_URL = (
  process.env.BETTER_AUTH_URL ||
  process.env.NEXT_PUBLIC_APP_URL ||
  "http://localhost:3000"
).replace(/\/$/, "");
const JWT_ISSUER = process.env.JWT_ISSUER || "mentorlagbe";
const JWT_AUDIENCE = process.env.JWT_AUDIENCE || "mentorlagbe";
const JWT_ALGORITHMS = (process.env.JWT_ALGORITHMS || "EdDSA")
  .split(",")
  .map((algorithm) => algorithm.trim())
  .filter(Boolean);

let remoteJwks = null;

function getRemoteJwks() {
  if (!remoteJwks) {
    remoteJwks = createRemoteJWKSet(new URL(`${AUTH_URL}/api/auth/jwks`));
  }

  return remoteJwks;
}

// The existing .env uses these exact names (including the "SECRED" typo).
const STRIPE_PUBLISH_KEY =
  process.env.STRIPE_PUBLISHABLE_KEY || process.env.STRIPE_PUBLISH_KEY || "";
const STRIPE_SECRET_KEY =
  process.env.STRIPE_SECRET_KEY || process.env.STRIPE_SECRED_KEY || "";
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || "";

const FREE_TUITION_LIMIT = 2;
const FREE_SAVED_TUITION_LIMIT = 5;

// Paid plans. Amounts are in cents and are used both for Checkout and as a
// fallback when a Stripe Session does not include amount_total.
const PRO_PLANS = {
  tutor_pro: {
    role: "tutor",
    amount: 1500, // $15.00
    name: "MentorLagbe Tutor Pro",
    description: "Unlimited tuition posts on MentorLagbe.",
    successPath: "/dashboard/tutor/post-tuition",
    cancelPath: "/dashboard/tutor/post-tuition",
  },
  student_pro: {
    role: "student",
    amount: 1000, // $10.00
    name: "MentorLagbe Student Pro",
    description: "Unlimited saved tuitions, Pro badge, and priority booking.",
    successPath: "/dashboard/student/upgrade-pro",
    cancelPath: "/dashboard/student/upgrade-pro",
    // Keep the assignment price in USD instead of letting Stripe present a
    // localized currency at checkout.
    adaptivePricing: false,
  },
};

const stripe = STRIPE_SECRET_KEY ? new Stripe(STRIPE_SECRET_KEY) : null;

const app = express();

// The browser normally talks to Express through the Next.js proxy (same
// origin), but direct clients are still supported. Never use "*" together with
// credentials; keep an explicit allowlist for local and deployed origins.
const ALLOWED_ORIGINS = Array.from(
  new Set(
    [
      CLIENT_URL,
      process.env.NEXT_PUBLIC_APP_URL,
      process.env.BETTER_AUTH_URL,
      process.env.VERCEL_URL ? `https://${process.env.VERCEL_URL}` : "",
      ...(process.env.CLIENT_URLS || "").split(","),
    ]
      .map((origin) => origin?.trim().replace(/\/$/, ""))
      .filter(Boolean)
  )
);

app.use(
  cors({
    origin(origin, callback) {
      // Same-origin/server-to-server requests have no Origin header.
      if (!origin || ALLOWED_ORIGINS.includes(origin)) {
        callback(null, true);
        return;
      }

      callback(null, false);
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

const client = new MongoClient(process.env.MONGODB_URI);

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

function parseCookies(cookieHeader = "") {
  return cookieHeader.split(";").reduce((cookies, part) => {
    const separator = part.indexOf("=");
    if (separator === -1) return cookies;

    const name = part.slice(0, separator).trim();
    const rawValue = part.slice(separator + 1).trim();

    try {
      cookies[name] = decodeURIComponent(rawValue);
    } catch {
      cookies[name] = rawValue;
    }

    return cookies;
  }, {});
}

function getSessionToken(req) {
  const cookies = parseCookies(req.headers.cookie || "");
  const signedToken =
    cookies["better-auth.session_token"] ??
    cookies["__Secure-better-auth.session_token"];

  if (!signedToken) return null;

  // BetterAuth stores the cookie as "<token>.<signature>".
  return signedToken.split(".")[0];
}

function toObjectId(id) {
  return ObjectId.isValid(String(id)) ? new ObjectId(String(id)) : null;
}

function toPublicTuition(doc) {
  if (!doc) return null;
  const { _id, ...rest } = doc;
  return { id: _id.toString(), ...rest };
}

function toPublicApplication(doc) {
  if (!doc) return null;
  const { _id, ...rest } = doc;

  return {
    id: _id.toString(),
    tuitionId: rest.tuitionId ? String(rest.tuitionId) : "",
    tuitionTitle: rest.tuitionTitle || "",
    studentId: rest.studentId || "",
    studentName:
      rest.studentName || rest.applicantName || rest.name || "Unknown student",
    studentEmail: rest.studentEmail || rest.email || "",
    studentPhone: rest.studentPhone || rest.phone || "",
    preferredSchedule: rest.preferredSchedule || rest.schedule || "",
    note: rest.note || rest.message || "",
    status: rest.status || "pending",
    // Student Pro applications are highlighted for tutors. The plan is joined
    // live (see withStudentPlans) so an upgrade applies to existing applications.
    studentPlan: rest.studentPlan === "pro" ? "pro" : "free",
    studentIsPro: rest.studentPlan === "pro",
    tutorId: rest.tutorId,
    tutorEmail: rest.tutorEmail,
    createdAt: rest.createdAt || rest.appliedAt,
    updatedAt: rest.updatedAt,
  };
}

function toPublicProfile(user) {
  if (!user) return null;

  return {
    id: String(user._id),
    name: user.name || "",
    email: user.email || "",
    phone: user.phone || "",
    address: user.address || "",
    bio: user.bio || "",
    image: user.image || "",
    role: user.role || "student",
    plan: user.plan || "free",
    proSince: user.proSince || null,
    createdAt: user.createdAt,
    updatedAt: user.updatedAt,
  };
}

function toAdminUser(user) {
  if (!user) return null;

  return {
    id: String(user._id),
    name: user.name || "",
    email: user.email || "",
    role: user.role || "student",
    plan: user.plan || "free",
    createdAt: user.createdAt || null,
    updatedAt: user.updatedAt || null,
  };
}

function withTuitionDetails(application, tuition) {
  const base = toPublicApplication(application);

  return {
    ...base,
    tuitionTitle: base.tuitionTitle || tuition?.title || "Untitled tuition",
    tuitionApprovalStatus: tuition?.approvalStatus,
    tuitionIsActive: tuition?.isActive,
  };
}

function ownsTuition(doc, user) {
  if (!doc) return false;

  if (doc.tutorId) return String(doc.tutorId) === user.id;

  return (
    typeof doc.tutorEmail === "string" &&
    doc.tutorEmail.toLowerCase() === user.email.toLowerCase()
  );
}

function ownerFilter(user) {
  return {
    $or: [
      { tutorId: user.id },
      // Legacy posts created before tutorId was stored.
      {
        $and: [
          { tutorEmail: user.email },
          { tutorId: { $in: [null, ""] } },
        ],
      },
    ],
  };
}

// Attach the student's current plan to applications. The plan is looked up
// live rather than snapshotted at apply time so Student Pro highlighting is
// immediately visible on existing applications after an upgrade.
async function withStudentPlans(db, applications) {
  if (!Array.isArray(applications) || applications.length === 0) {
    return [];
  }

  const studentIds = [
    ...new Set(
      applications.map((application) => application.studentId).filter(Boolean)
    ),
  ]
    .map(toObjectId)
    .filter(Boolean);

  const planByStudent = new Map();

  if (studentIds.length > 0) {
    const students = await db
      .collection("user")
      .find({ _id: { $in: studentIds } })
      .project({ plan: 1 })
      .toArray();

    for (const student of students) {
      planByStudent.set(
        String(student._id),
        student.plan === "pro" ? "pro" : "free"
      );
    }
  }

  return applications.map((application) => {
    const plan = planByStudent.get(String(application.studentId)) || "free";

    return {
      ...application,
      studentPlan: plan,
      studentIsPro: plan === "pro",
    };
  });
}

// Pro students get priority in the tutor's applicant queue. Keep newest-first
// ordering within each plan group.
function sortApplicationsByStudentPriority(applications) {
  return [...applications].sort((left, right) => {
    if (left.studentIsPro !== right.studentIsPro) {
      return left.studentIsPro ? -1 : 1;
    }

    return (
      new Date(right.createdAt || 0).getTime() -
      new Date(left.createdAt || 0).getTime()
    );
  });
}

// Marks a verified Stripe Checkout Session as paid and upgrades the buyer.
// This is the only place a user's plan is changed, so an upgrade can never
// happen without Stripe confirming the payment.
async function completeCheckoutSession(db, session) {
  if (!session?.id || session.payment_status !== "paid") return null;

  const userId =
    session.metadata?.userId || session.client_reference_id || "";
  const userObjectId = toObjectId(userId);
  if (!userObjectId) return null;

  // Only sessions created by /payments/checkout for one of our paid plans may
  // upgrade a plan. This prevents an unrelated paid session from being used.
  const plan = session.metadata?.plan;
  const planConfig = PRO_PLANS[plan];
  if (!planConfig) return null;

  const users = db.collection("user");
  const user = await users.findOne({ _id: userObjectId });
  if (!user || user.role !== planConfig.role) return null;

  const payments = db.collection("payments");
  const existing = await payments.findOne({ stripeSessionId: session.id });

  if (existing?.status === "completed") {
    return { userId, plan, alreadyCompleted: true };
  }

  const now = new Date();
  const paymentIntentId =
    typeof session.payment_intent === "string"
      ? session.payment_intent
      : session.payment_intent?.id || "";

  const paymentUpdate = {
    userId,
    userEmail:
      session.customer_email || session.customer_details?.email || "",
    plan,
    amount: session.amount_total ?? planConfig.amount,
    currency: session.currency || "usd",
    stripePaymentIntentId: paymentIntentId,
    status: "completed",
    completedAt: now,
    updatedAt: now,
  };

  // Claim the pending payment atomically so concurrent webhook/verify calls
  // cannot both apply the same upgrade. A filtered update only matches a
  // record that is not already completed; if another request won the race we
  // treat this call as an idempotent replay.
  let claimed = null;

  try {
    claimed = await payments.findOneAndUpdate(
      { stripeSessionId: session.id, status: { $ne: "completed" } },
      { $set: paymentUpdate, $setOnInsert: { createdAt: now } },
      { upsert: true, returnDocument: "after" }
    );
  } catch (error) {
    if (error?.code !== 11000) throw error;

    // A concurrent upsert hit the unique stripeSessionId index. Re-read below
    // and treat an already-completed record as a replay.
  }

  if (!claimed) {
    const current = await payments.findOne({ stripeSessionId: session.id });

    if (current?.status === "completed") {
      return { userId, plan, alreadyCompleted: true };
    }

    // The pending record was missing and the upsert conflicted; create or
    // complete it now.
    await payments.updateOne(
      { stripeSessionId: session.id },
      { $set: paymentUpdate, $setOnInsert: { createdAt: now } },
      { upsert: true }
    );
  }

  await users.updateOne(
    { _id: userObjectId },
    { $set: { plan: "pro", proSince: now, updatedAt: now } }
  );

  return { userId, plan, alreadyCompleted: false };
}

function toAuthUser(user) {
  if (!user) return null;

  return {
    id: String(user._id),
    name: user.name || "",
    email: user.email || "",
    role: user.role || "student",
    plan: user.plan || "free",
    proSince: user.proSince || null,
    phone: user.phone || "",
  };
}

async function findAuthUserById(db, id) {
  if (!id) return null;

  const userId = toObjectId(id);
  const user = await db
    .collection("user")
    .findOne(userId ? { _id: userId } : { id: String(id) });

  return toAuthUser(user);
}

// Primary authentication path: verify the BetterAuth JWT with the public JWKS
// and load the fresh user from MongoDB. Loading the user (rather than trusting
// JWT claims alone) means role and plan changes are effective immediately.
async function getJwtUser(req, db) {
  const authorization = req.headers.authorization || "";

  if (!authorization.startsWith("Bearer ")) return null;

  const token = authorization.slice("Bearer ".length).trim();
  if (!token) return null;

  try {
    const { payload } = await jwtVerify(token, getRemoteJwks(), {
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE,
      algorithms: JWT_ALGORITHMS,
    });

    const userId = payload.sub || payload.userId || payload.id;
    return await findAuthUserById(db, userId);
  } catch (error) {
    console.warn("JWT verification failed:", error.message);
    return null;
  }
}

// Backwards-compatible fallback for direct clients that still send the
// BetterAuth session cookie (for example local scripts or older deployments).
async function getSessionUser(req, db) {
  const token = getSessionToken(req);
  if (!token) return null;

  const session = await db.collection("session").findOne({ token });
  if (!session) return null;

  if (session.expiresAt && new Date(session.expiresAt).getTime() < Date.now()) {
    return null;
  }

  return findAuthUserById(db, session.userId);
}

async function getAuthUser(req, db) {
  return (await getJwtUser(req, db)) || (await getSessionUser(req, db));
}

function verifyToken(db) {
  return async (req, res, next) => {
    try {
      const user = await getAuthUser(req, db);

      if (!user) {
        res.status(401).json({ message: "Please sign in to continue." });
        return;
      }

      req.user = user;
      next();
    } catch (error) {
      next(error);
    }
  };
}

// Role guards. They must always run after verifyToken so the role comes from
// MongoDB and is never taken from the client or from stale JWT claims.
function verifyStudent(req, res, next) {
  if (req.user?.role !== "student") {
    res.status(403).json({ message: "Only students can access this resource." });
    return;
  }

  next();
}

function verifyTutor(req, res, next) {
  if (req.user?.role !== "tutor") {
    res.status(403).json({ message: "Only tutors can access this resource." });
    return;
  }

  next();
}

function verifyAdmin(req, res, next) {
  if (req.user?.role !== "admin") {
    res.status(403).json({ message: "Only admins can access this resource." });
    return;
  }

  next();
}

function toPlanName(plan) {
  if (plan === "student_pro") return "Student Pro";
  if (plan === "tutor_pro") return "Tutor Pro";

  if (!plan) return "—";

  return String(plan)
    .split("_")
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function validateTuitionUpdate(body = {}) {
  const update = {};
  const errors = [];

  if (body.title !== undefined) {
    const title = typeof body.title === "string" ? body.title.trim() : "";
    if (title.length < 5) errors.push("Title must be at least 5 characters.");
    else update.title = title;
  }

  if (body.subject !== undefined) {
    const subject = typeof body.subject === "string" ? body.subject.trim() : "";
    if (!subject) errors.push("Subject is required.");
    else update.subject = subject;
  }

  if (body.classLevel !== undefined) {
    const classLevel =
      typeof body.classLevel === "string" ? body.classLevel.trim() : "";
    if (!classLevel) errors.push("Class level is required.");
    else update.classLevel = classLevel;
  }

  if (body.mode !== undefined) {
    if (!["Online", "Offline"].includes(body.mode)) {
      errors.push("Mode must be Online or Offline.");
    } else {
      update.mode = body.mode;
    }
  }

  if (body.monthlyFee !== undefined) {
    const monthlyFee = Number(body.monthlyFee);
    if (!Number.isFinite(monthlyFee) || monthlyFee <= 0) {
      errors.push("Monthly fee must be greater than 0.");
    } else {
      update.monthlyFee = monthlyFee;
    }
  }

  if (body.daysPerWeek !== undefined) {
    const daysPerWeek = Number(body.daysPerWeek);
    if (!Number.isInteger(daysPerWeek) || daysPerWeek < 1 || daysPerWeek > 7) {
      errors.push("Days per week must be between 1 and 7.");
    } else {
      update.daysPerWeek = daysPerWeek;
    }
  }

  if (body.description !== undefined) {
    const description =
      typeof body.description === "string" ? body.description.trim() : "";
    if (description.length < 20) {
      errors.push("Description must be at least 20 characters.");
    } else {
      update.description = description;
    }
  }

  if (body.bannerImage !== undefined) {
    if (typeof body.bannerImage !== "string") {
      errors.push("Banner image must be a URL string.");
    } else {
      update.bannerImage = body.bannerImage;
    }
  }

  if (Object.keys(update).length === 0 && errors.length === 0) {
    errors.push("No changes were provided.");
  }

  return { update, errors };
}

/* ------------------------------------------------------------------ */
/* Server                                                              */
/* ------------------------------------------------------------------ */

async function startServer() {
  await client.connect();
  console.log("You successfully connected to MongoDB!");

  const db = client.db(DB_NAME);
  const tuitions = db.collection("tuitions");
  const applications = db.collection("applications");
  const payments = db.collection("payments");
  const savedTuitions = db.collection("savedTuitions");
  const usersCollection = db.collection("user");
  const auth = verifyToken(db);

  
  try {
    await applications.createIndexes([
      {
        key: { tuitionId: 1, studentId: 1 },
        unique: true,
        name: "unique_tuition_student",
      },
      {
        key: { tuitionId: 1, createdAt: -1 },
        name: "tuition_recent",
      },
    ]);

    // Older installs created a non-sparse unique index on stripeSessionId.
    // PaymentIntent documents don't have that field, so recreate it as sparse.
    try {
      const paymentIndexes = await payments.indexes();
      const sessionIndex = paymentIndexes.find(
        (index) => index.name === "unique_stripe_session"
      );

      if (sessionIndex && !sessionIndex.sparse) {
        await payments.dropIndex("unique_stripe_session");
      }
    } catch (error) {
      // The collection or index may not exist yet.
    }

    await payments.createIndexes([
      {
        key: { stripeSessionId: 1 },
        unique: true,
        sparse: true,
        name: "unique_stripe_session",
      },
      {
        key: { stripePaymentIntentId: 1 },
        unique: true,
        sparse: true,
        name: "unique_stripe_intent",
      },
      {
        key: { userId: 1, createdAt: -1 },
        name: "user_payments",
      },
    ]);

    await savedTuitions.createIndexes([
      {
        key: { studentId: 1, tuitionId: 1 },
        unique: true,
        name: "unique_student_saved_tuition",
      },
      {
        key: { studentId: 1, createdAt: -1 },
        name: "student_saved_recent",
      },
    ]);
  } catch (error) {
    console.error("Failed to create indexes:", error.message);
  }

  if (!stripe) {
    console.warn("Stripe secret key is missing. Checkout will be unavailable.");
  } else {
    const mode = STRIPE_SECRET_KEY.startsWith("sk_live") ? "live" : "test";
    console.log(`Stripe ${mode} mode enabled.`);
  }
  if (!STRIPE_WEBHOOK_SECRET) {
    console.warn(
      "STRIPE_WEBHOOK_SECRET is missing. Stripe webhooks will be rejected."
    );
  }

  /* ------------------------ Stripe webhook ------------------------ */
  // Registered before express.json() so Stripe receives the raw body needed
  // for signature verification.
  app.post(
    "/payments/webhook",
    express.raw({ type: "application/json" }),
    async (req, res) => {
      if (!stripe || !STRIPE_WEBHOOK_SECRET) {
        res.status(500).json({ message: "Stripe webhook is not configured." });
        return;
      }

      const signature = req.headers["stripe-signature"];
      if (!signature) {
        res.status(400).json({ message: "Missing Stripe signature." });
        return;
      }

      let event;
      try {
        event = stripe.webhooks.constructEvent(
          req.body,
          signature,
          STRIPE_WEBHOOK_SECRET
        );
      } catch (error) {
        console.error(
          "Stripe webhook signature verification failed:",
          error.message
        );
        res.status(400).json({ message: "Invalid Stripe webhook signature." });
        return;
      }

      try {
        if (
          event.type === "checkout.session.completed" ||
          event.type === "checkout.session.async_payment_succeeded"
        ) {
          await completeCheckoutSession(db, event.data.object);
        } else if (
          event.type === "checkout.session.expired" ||
          event.type === "checkout.session.async_payment_failed"
        ) {
          await payments.updateOne(
            { stripeSessionId: event.data.object.id, status: "pending" },
            { $set: { status: "failed", updatedAt: new Date() } }
          );
        }

        res.json({ received: true });
      } catch (error) {
        console.error("Failed to process Stripe webhook:", error);
        res.status(500).json({ message: "Failed to process webhook." });
      }
    }
  );

  app.use(express.json());

  app.get("/health", (req, res) => {
    res.send({ status: "ok" });
  });
//          my get applications



  app.get("/student/applications", auth, verifyStudent, async (req, res) => {
  try {
    if (req.user.role !== "student") {
      return res.status(403).json({
        message: "Only students can access their applications.",
      });
    }

    const data = await applications
      .find({ studentId: req.user.id })
      .sort({ createdAt: -1 })
      .toArray();

    const tuitionIds = data
      .map((application) => toObjectId(application.tuitionId))
      .filter(Boolean);

    const tuitionData = await tuitions
      .find({ _id: { $in: tuitionIds } })
      .toArray();

    const tuitionMap = new Map(
      tuitionData.map((tuition) => [
        tuition._id.toString(),
        tuition,
      ])
    );

    const result = data.map((application) => {
      const tuition = tuitionMap.get(application.tuitionId);

      return {
        ...toPublicApplication(application),
        tutorName: tuition?.tutorName || "Unknown Tutor",
        tutorEmail: application.tutorEmail || tuition?.tutorEmail || "",
        monthlyFee: Number(tuition?.monthlyFee) || 0,
      };
    });

    res.send(result);
  } catch (error) {
    console.error("Get student applications error:", error);

    res.status(500).json({
      message: "Failed to load applications.",
    });
  }
});
//     cenceled applications

app.patch("/applications/:id/withdraw", auth, verifyStudent, async (req, res) => {
  try {
    if (req.user.role !== "student") {
      return res.status(403).json({
        message: "Only students can cancel applications.",
      });
    }

    const applicationId = toObjectId(req.params.id);

    if (!applicationId) {
      return res.status(400).json({
        message: "Invalid application ID.",
      });
    }

    const application = await applications.findOne({
      _id: applicationId,
    });

    if (!application) {
      return res.status(404).json({
        message: "Application not found.",
      });
    }

    if (application.studentId !== req.user.id) {
      return res.status(403).json({
        message: "You cannot cancel someone else's application.",
      });
    }

    if (application.status !== "pending") {
      return res.status(400).json({
        message: "Only pending applications can be cancelled.",
      });
    }

    const result = await applications.updateOne({
      _id: applicationId,
      studentId: req.user.id,
      status: "pending",
    }, {
      $set: { status: "withdrawn", updatedAt: new Date() },
    });

    if (result.modifiedCount === 0) {
      return res.status(400).json({
        message: "Application could not be cancelled.",
      });
    }

    res.send({
      message: "Application cancelled successfully.",
      status: "withdrawn",
    });
  } catch (error) {
    console.error("Cancel application error:", error);

    res.status(500).json({
      message: "Failed to cancel application.",
    });
  }
});
  /* ------------------------ Student overview ------------------------ */

  // Aggregate dashboard data for the signed-in student only.
  app.get("/student/overview", auth, verifyStudent, async (req, res) => {
    try {
      if (req.user.role !== "student") {
        return res.status(403).json({
          message: "Only students can access the student dashboard.",
        });
      }

      const applicationFilter = { studentId: req.user.id };

      const [
        totalApplications,
        pendingApplications,
        acceptedApplications,
        rejectedApplications,
        savedCount,
        recentApplications,
      ] = await Promise.all([
        applications.countDocuments(applicationFilter),
        applications.countDocuments({ ...applicationFilter, status: "pending" }),
        applications.countDocuments({
          ...applicationFilter,
          status: "accepted",
        }),
        applications.countDocuments({
          ...applicationFilter,
          status: "rejected",
        }),
        savedTuitions.countDocuments({ studentId: req.user.id }),
        applications
          .find(applicationFilter)
          .sort({ createdAt: -1 })
          .limit(5)
          .toArray(),
      ]);

      const tuitionIds = recentApplications
        .map((application) => toObjectId(application.tuitionId))
        .filter(Boolean);

      const tuitionData = tuitionIds.length
        ? await tuitions.find({ _id: { $in: tuitionIds } }).toArray()
        : [];
      const tuitionMap = new Map(
        tuitionData.map((tuition) => [String(tuition._id), tuition])
      );

      res.json({
        stats: {
          totalApplications,
          pendingApplications,
          acceptedApplications,
          rejectedApplications,
          savedTuitions: savedCount,
          plan: req.user.plan || "free",
        },
        recentApplications: recentApplications.map((application) => {
          const tuition = tuitionMap.get(String(application.tuitionId));

          return {
            ...toPublicApplication(application),
            tutorName: tuition?.tutorName || "Unknown Tutor",
            tutorEmail: application.tutorEmail || tuition?.tutorEmail || "",
            monthlyFee: Number(tuition?.monthlyFee) || 0,
          };
        }),
      });
    } catch (error) {
      console.error("Student overview error:", error);
      res.status(500).json({ message: "Failed to load your dashboard." });
    }
  });

  /* ------------------------ Student plan ------------------------ */

  // Current plan and Student Pro price for the signed-in student.
  app.get("/student/plan", auth, verifyStudent, async (req, res) => {
    try {
      if (req.user.role !== "student") {
        return res.status(403).json({
          message: "Only students can access the student plan.",
        });
      }

      const plan = req.user.plan === "pro" ? "pro" : "free";
      const isPro = plan === "pro";
      const savedCount = await savedTuitions.countDocuments({
        studentId: req.user.id,
      });
      const savedLimit = isPro ? null : FREE_SAVED_TUITION_LIMIT;

      res.json({
        plan,
        status: isPro ? "active" : "free",
        isPro,
        price: PRO_PLANS.student_pro.amount,
        currency: "usd",
        // Student Pro is a one-time purchase in the blueprint, so there is no
        // expiry date. Stripe Checkout session expiry is handled by the
        // webhook (checkout.session.expired) without ever downgrading a user.
        since: isPro ? req.user.proSince || null : null,
        expiresAt: null,
        savedCount,
        savedLimit,
        canSaveMore: isPro || savedCount < FREE_SAVED_TUITION_LIMIT,
      });
    } catch (error) {
      console.error("Student plan error:", error);
      res.status(500).json({ message: "Failed to load your plan." });
    }
  });

  /* ------------------------ Saved tuitions ------------------------ */

  // Saved tuition posts for the signed-in student, newest first.
  app.get("/saved-tuitions", auth, verifyStudent, async (req, res) => {
    try {
      if (req.user.role !== "student") {
        return res.status(403).json({
          message: "Only students can access saved tuitions.",
        });
      }

      const saved = await savedTuitions
        .find({ studentId: req.user.id })
        .sort({ createdAt: -1 })
        .toArray();

      const tuitionIds = saved
        .map((entry) => toObjectId(entry.tuitionId))
        .filter(Boolean);

      if (tuitionIds.length === 0) {
        return res.json([]);
      }

      const tuitionData = await tuitions
        .find({ _id: { $in: tuitionIds } })
        .toArray();
      const tuitionMap = new Map(
        tuitionData.map((tuition) => [String(tuition._id), tuition])
      );

      const result = saved
        .map((entry) => {
          const tuition = tuitionMap.get(String(entry.tuitionId));
          if (!tuition) return null;

          return {
            ...toPublicTuition(tuition),
            savedAt: entry.createdAt,
          };
        })
        .filter(Boolean);

      res.json(result);
    } catch (error) {
      console.error("Get saved tuitions error:", error);
      res.status(500).json({ message: "Failed to load saved tuitions." });
    }
  });

  // Save a tuition for the signed-in student. Saving twice is a no-op.
  app.post("/saved-tuitions", auth, verifyStudent, async (req, res) => {
    try {
      if (req.user.role !== "student") {
        return res.status(403).json({
          message: "Only students can save tuitions.",
        });
      }

      const tuitionId =
        typeof req.body?.tuitionId === "string" ? req.body.tuitionId : "";
      const tuitionObjectId = toObjectId(tuitionId);

      if (!tuitionObjectId) {
        return res.status(400).json({ message: "Invalid tuition ID." });
      }

      const tuition = await tuitions.findOne({ _id: tuitionObjectId });

      if (!tuition) {
        return res.status(404).json({ message: "Tuition not found." });
      }

      if (
        tuition.approvalStatus !== "approved" ||
        tuition.isActive === false
      ) {
        return res.status(422).json({
          message: "Only approved, active tuitions can be saved.",
        });
      }

      const existing = await savedTuitions.findOne({
        studentId: req.user.id,
        tuitionId: String(tuition._id),
      });

      // Saving the same tuition twice stays a no-op, even when the free plan
      // is already at its bookmark limit.
      if (existing) {
        return res.json({
          tuitionId: String(tuition._id),
          saved: true,
          message: "Tuition already saved.",
        });
      }

      if (req.user.plan !== "pro") {
        const savedCount = await savedTuitions.countDocuments({
          studentId: req.user.id,
        });

        if (savedCount >= FREE_SAVED_TUITION_LIMIT) {
          return res.status(403).json({
            code: "PLAN_LIMIT",
            message: `Free plan allows up to ${FREE_SAVED_TUITION_LIMIT} saved tuitions. Upgrade to Student Pro for unlimited bookmarks.`,
            plan: "free",
            limit: FREE_SAVED_TUITION_LIMIT,
            savedCount,
          });
        }
      }

      await savedTuitions.updateOne(
        { studentId: req.user.id, tuitionId: String(tuition._id) },
        { $setOnInsert: { createdAt: new Date() } },
        { upsert: true }
      );

      res.status(201).json({
        tuitionId: String(tuition._id),
        saved: true,
        message: "Tuition saved.",
      });
    } catch (error) {
      if (error?.code === 11000) {
        return res.json({
          tuitionId: req.body?.tuitionId,
          saved: true,
          message: "Tuition already saved.",
        });
      }

      console.error("Save tuition error:", error);
      res.status(500).json({ message: "Failed to save tuition." });
    }
  });

  // Remove a saved tuition. Removing something that is not saved is a no-op.
  app.delete("/saved-tuitions/:tuitionId", auth, verifyStudent, async (req, res) => {
    try {
      if (req.user.role !== "student") {
        return res.status(403).json({
          message: "Only students can remove saved tuitions.",
        });
      }

      const tuitionObjectId = toObjectId(req.params.tuitionId);

      if (!tuitionObjectId) {
        return res.status(400).json({ message: "Invalid tuition ID." });
      }

      await savedTuitions.deleteOne({
        studentId: req.user.id,
        tuitionId: String(tuitionObjectId),
      });

      res.json({
        tuitionId: String(tuitionObjectId),
        saved: false,
        message: "Tuition removed from saved list.",
      });
    } catch (error) {
      console.error("Remove saved tuition error:", error);
      res.status(500).json({ message: "Failed to remove saved tuition." });
    }
  });

  /* ------------------------ Profile Update ------------------------ */

  // Full profile for the signed-in user. BetterAuth's session does not include
  // optional profile fields (phone/address/bio), so the profile page needs a
  // dedicated read endpoint.
  app.get("/profile", auth, async (req, res) => {
    try {
      const userId = toObjectId(req.user.id);

      if (!userId) {
        return res.status(400).json({ message: "Invalid user ID." });
      }

      const user = await db.collection("user").findOne({ _id: userId });

      if (!user) {
        return res.status(404).json({ message: "User not found." });
      }

      res.json(toPublicProfile(user));
    } catch (error) {
      console.error("Profile read error:", error);
      res.status(500).json({ message: "Failed to load your profile." });
    }
  });

  // Partial profile update. Email, role, and plan can never be changed here.
  app.patch("/profile", auth, async (req, res) => {
    try {
      const { name, phone, address, bio, image } = req.body ?? {};
      const update = {};

      if (name !== undefined) {
        if (typeof name !== "string" || !name.trim()) {
          return res.status(400).json({ message: "Name is required." });
        }
        if (name.trim().length > 80) {
          return res
            .status(400)
            .json({ message: "Name must be 80 characters or fewer." });
        }
        update.name = name.trim();
      }

      if (phone !== undefined) {
        if (typeof phone !== "string") {
          return res.status(400).json({ message: "Phone must be a string." });
        }
        if (phone.trim().length > 30) {
          return res
            .status(400)
            .json({ message: "Phone must be 30 characters or fewer." });
        }
        update.phone = phone.trim();
      }

      if (address !== undefined) {
        if (typeof address !== "string") {
          return res.status(400).json({ message: "Address must be a string." });
        }
        if (address.trim().length > 200) {
          return res
            .status(400)
            .json({ message: "Address must be 200 characters or fewer." });
        }
        update.address = address.trim();
      }

      if (bio !== undefined) {
        if (typeof bio !== "string") {
          return res.status(400).json({ message: "Bio must be a string." });
        }
        if (bio.trim().length > 1000) {
          return res
            .status(400)
            .json({ message: "Bio must be 1000 characters or fewer." });
        }
        update.bio = bio.trim();
      }

      if (image !== undefined) {
        if (typeof image !== "string") {
          return res.status(400).json({ message: "Image must be a URL string." });
        }
        update.image = image.trim();
      }

      if (Object.keys(update).length === 0) {
        return res.status(400).json({ message: "No changes were provided." });
      }

      const userId = toObjectId(req.user.id);

      if (!userId) {
        return res.status(400).json({ message: "Invalid user ID." });
      }

      const updatedUser = await db.collection("user").findOneAndUpdate(
        { _id: userId },
        { $set: { ...update, updatedAt: new Date() } },
        { returnDocument: "after" }
      );

      if (!updatedUser) {
        return res.status(404).json({ message: "User not found." });
      }

      res.json({
        message: "Profile updated successfully.",
        user: toPublicProfile(updatedUser),
      });
    } catch (error) {
      console.error("Profile update error:", error);
      res.status(500).json({ message: "Failed to update profile." });
    }
  });

  /* ---------------------------- Create ---------------------------- */

  app.post("/add-tuitions", auth, verifyTutor, async (req, res) => {
    try {
      const {
        title,
        subject,
        classLevel,
        mode,
        monthlyFee,
        daysPerWeek,
        description,
        bannerImage,
      } = req.body ?? {};

      if (req.user.role !== "tutor") {
        res.status(403).json({ message: "Only tutors can post tuitions." });
        return;
      }

      const titleText = typeof title === "string" ? title.trim() : "";
      const subjectText = typeof subject === "string" ? subject.trim() : "";
      const classLevelText =
        typeof classLevel === "string" ? classLevel.trim() : "";
      const descriptionText =
        typeof description === "string" ? description.trim() : "";
      const modeText = typeof mode === "string" ? mode.trim() : "";
      const monthlyFeeValue = Number(monthlyFee);
      const daysPerWeekValue = Number(daysPerWeek ?? 3);

      if (!titleText || !subjectText || !classLevelText || !descriptionText) {
        res.status(400).send({ message: "Missing required tuition fields." });
        return;
      }

      if (titleText.length < 5 || titleText.length > 120) {
        res.status(400).send({
          message: "Title must be between 5 and 120 characters.",
        });
        return;
      }

      if (subjectText.length > 80 || classLevelText.length > 60) {
        res.status(400).send({ message: "Subject or class level is too long." });
        return;
      }

      if (!["Online", "Offline"].includes(modeText)) {
        res.status(400).send({ message: "Mode must be Online or Offline." });
        return;
      }

      if (!Number.isFinite(monthlyFeeValue) || monthlyFeeValue <= 0) {
        res.status(400).send({
          message: "Monthly fee must be greater than 0.",
        });
        return;
      }

      if (
        !Number.isInteger(daysPerWeekValue) ||
        daysPerWeekValue < 1 ||
        daysPerWeekValue > 7
      ) {
        res.status(400).send({
          message: "Days per week must be between 1 and 7.",
        });
        return;
      }

      if (descriptionText.length < 30 || descriptionText.length > 2000) {
        res.status(400).send({
          message: "Description must be between 30 and 2000 characters.",
        });
        return;
      }

      // Free tutors may own at most two tuitions. Pro tutors are unlimited.
      if (req.user.plan !== "pro") {
        const tuitionCount = await tuitions.countDocuments(
          ownerFilter(req.user)
        );

        if (tuitionCount >= FREE_TUITION_LIMIT) {
          res.status(403).json({
            code: "PLAN_LIMIT",
            message: `Free plan allows up to ${FREE_TUITION_LIMIT} tuition posts. Upgrade to Pro for unlimited posting.`,
            plan: "free",
            limit: FREE_TUITION_LIMIT,
            tuitionCount,
          });
          return;
        }
      }

      const now = new Date();
      const result = await tuitions.insertOne({
        title: titleText,
        subject: subjectText,
        classLevel: classLevelText,
        mode: modeText,
        monthlyFee: monthlyFeeValue,
        daysPerWeek: daysPerWeekValue,
        description: descriptionText,
        bannerImage: typeof bannerImage === "string" ? bannerImage : "",
        tutorId: req.user.id,
        tutorName: req.user.name,
        tutorEmail: req.user.email,
        approvalStatus: "pending",
        isActive: true,
        createdAt: now,
        updatedAt: now,
      });

      res.status(201).send({
        message: "Tuition posted successfully.",
        insertedId: result.insertedId,
      });
    } catch (err) {
      console.error(err);
      res.status(500).send({ message: "Failed to add tuition." });
    }
  });

  /* ----------------------------- Read ----------------------------- */

  // Public list kept for backwards compatibility with the existing action.
app.get("/add-tuitions", async (req, res) => {
  try {
    const {
      q,
      subject,
      classLevel,
      mode,
      minFee,
      maxFee,
    } = req.query;

    const query = {
      approvalStatus: "approved",
      isActive: { $ne: false },
    };

    // Search tuition title using case-insensitive regex
    if (q && typeof q === "string" && q.trim()) {
      const escapedSearch = q.trim().replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

      query.title = {
        $regex: escapedSearch,
        $options: "i",
      };
    }

    // Subject filter
    if (subject && typeof subject === "string") {
      query.subject = subject;
    }

    // Class level filter
    if (classLevel && typeof classLevel === "string") {
      query.classLevel = classLevel;
    }

    // Online / Offline filter
    if (mode && typeof mode === "string") {
      query.mode = {
        $regex: `^${mode}$`,
        $options: "i",
      };
    }

    // Monthly fee range
    const feeFilter = {};

    if (minFee !== undefined) {
      const min = Number(minFee);

      if (Number.isFinite(min) && min >= 0) {
        feeFilter.$gte = min;
      }
    }

    if (maxFee !== undefined) {
      const max = Number(maxFee);

      if (Number.isFinite(max) && max >= 0) {
        feeFilter.$lte = max;
      }
    }

    if (Object.keys(feeFilter).length > 0) {
      query.monthlyFee = feeFilter;
    }

    const data = await tuitions
      .find(query)
      .sort({ createdAt: -1 })
      .toArray();

    res.send(data);
  } catch (error) {
    console.error("Browse tuitions error:", error);

    res.status(500).send({
      message: "Failed to fetch tuitions",
    });
  }
});

  // Public tuition details used by the student catalogue.  Keep this separate
  // from the tutor-only management route below so a student can never read a
  // pending, rejected, or closed post by guessing its id.
  app.get("/public-tuitions/:id", async (req, res) => {
    const id = toObjectId(req.params.id);
    if (!id) {
      res.status(404).json({ message: "Tuition not found." });
      return;
    }

    const tuition = await tuitions.findOne({
      _id: id,
      approvalStatus: "approved",
      isActive: { $ne: false },
    });

    if (!tuition) {
      res.status(404).json({ message: "Tuition not found or no longer available." });
      return;
    }

    res.json(toPublicTuition(tuition));
  });

  // Only the logged-in tutor's tuitions. Must be declared before "/tuitions/:id".
  app.get("/tuitions/mine", auth, verifyTutor, async (req, res) => {
    const data = await tuitions
      .find(ownerFilter(req.user))
      .sort({ createdAt: -1 })
      .toArray();

    res.json(
      await Promise.all(
        data.map(async (tuition) => ({
          ...toPublicTuition(tuition),
          applicationsCount: await applications.countDocuments({
            tuitionId: String(tuition._id),
          }),
        }))
      )
    );
  });

  app.get("/tuitions/:id", auth, verifyTutor, async (req, res) => {
    const id = toObjectId(req.params.id);
    if (!id) {
      res.status(404).json({ message: "Tuition not found." });
      return;
    }

    const tuition = await tuitions.findOne({ _id: id });
    if (!tuition) {
      res.status(404).json({ message: "Tuition not found." });
      return;
    }

    if (!ownsTuition(tuition, req.user)) {
      res.status(403).json({ message: "You can only manage your own tuitions." });
      return;
    }

    res.json(toPublicTuition(tuition));
  });

  /* ---------------------------- Update ---------------------------- */

  app.patch("/tuitions/:id", auth, verifyTutor, async (req, res) => {
    const id = toObjectId(req.params.id);
    if (!id) {
      res.status(404).json({ message: "Tuition not found." });
      return;
    }

    const tuition = await tuitions.findOne({ _id: id });
    if (!tuition) {
      res.status(404).json({ message: "Tuition not found." });
      return;
    }

    if (!ownsTuition(tuition, req.user)) {
      res.status(403).json({ message: "You can only manage your own tuitions." });
      return;
    }

    const { update, errors } = validateTuitionUpdate(req.body);
    if (errors.length > 0) {
      res.status(400).json({ message: errors[0] });
      return;
    }

    // approvalStatus and isActive are intentionally excluded from client input.
    // A corrected rejection must be moderated again before becoming public.
    if (tuition.approvalStatus === "rejected") {
      update.approvalStatus = "pending";
      update.isActive = true;
      update.rejectionReason = "";
    }
    const updated = await tuitions.findOneAndUpdate(
      { _id: id },
      { $set: { ...update, updatedAt: new Date() } },
      { returnDocument: "after" }
    );

    res.json(toPublicTuition(updated));
  });

  app.patch("/tuitions/:id/active", auth, verifyTutor, async (req, res) => {
    const id = toObjectId(req.params.id);
    if (!id) {
      res.status(404).json({ message: "Tuition not found." });
      return;
    }

    if (typeof req.body?.isActive !== "boolean") {
      res.status(400).json({ message: "isActive must be true or false." });
      return;
    }

    const tuition = await tuitions.findOne({ _id: id });
    if (!tuition) {
      res.status(404).json({ message: "Tuition not found." });
      return;
    }

    if (!ownsTuition(tuition, req.user)) {
      res.status(403).json({ message: "You can only manage your own tuitions." });
      return;
    }

    if (tuition.approvalStatus !== "approved") {
      res.status(422).json({
        message: "Only approved tuitions can be activated or closed.",
      });
      return;
    }

    const updated = await tuitions.findOneAndUpdate(
      { _id: id },
      { $set: { isActive: req.body.isActive, updatedAt: new Date() } },
      { returnDocument: "after" }
    );

    res.json(toPublicTuition(updated));
  });

  /* ---------------------------- Delete ---------------------------- */

  app.delete("/tuitions/:id", auth, verifyTutor, async (req, res) => {
    const id = toObjectId(req.params.id);
    if (!id) {
      res.status(404).json({ message: "Tuition not found." });
      return;
    }

    const tuition = await tuitions.findOne({ _id: id });
    if (!tuition) {
      res.status(404).json({ message: "Tuition not found." });
      return;
    }

    if (!ownsTuition(tuition, req.user)) {
      res.status(403).json({ message: "You can only manage your own tuitions." });
      return;
    }

    const acceptedApplication = await applications.findOne({
      tuitionId: String(id),
      status: "accepted",
    });

    if (acceptedApplication) {
      res.status(422).json({
        message: "An accepted tuition cannot be deleted. Close it instead.",
      });
      return;
    }

    await applications.deleteMany({ tuitionId: String(id) });
    await tuitions.deleteOne({ _id: id });
    res.json({ message: "Tuition deleted successfully." });
  });

  /* ------------------------- Applications ------------------------- */

  // Student-facing create endpoint (used by the future apply flow and tests).
  app.post("/applications", auth, verifyStudent, async (req, res) => {
    try {
      if (req.user.role !== "student") {
        res.status(403).json({ message: "Only students can apply to tuitions." });
        return;
      }

      const { tuitionId, note, preferredSchedule, phone } = req.body ?? {};
      const tuitionObjectId = toObjectId(tuitionId);

      if (!tuitionObjectId) {
        res.status(404).json({ message: "Tuition not found." });
        return;
      }

      const noteText = typeof note === "string" ? note.trim() : "";
      if (noteText.length < 20 || noteText.length > 1000) {
        res.status(400).json({
          message: "Your note must be between 20 and 1000 characters.",
        });
        return;
      }

      const tuition = await tuitions.findOne({ _id: tuitionObjectId });
      if (!tuition) {
        res.status(404).json({ message: "Tuition not found." });
        return;
      }

      if (
        tuition.approvalStatus !== "approved" ||
        tuition.isActive === false
      ) {
        res.status(422).json({
          message: "Applications are only open for approved, active tuitions.",
        });
        return;
      }

      const existing = await applications.findOne({
        tuitionId: String(tuition._id),
        studentId: req.user.id,
      });

      if (existing) {
        res.status(409).json({ message: "You have already applied to this tuition." });
        return;
      }

      const now = new Date();
      const document = {
        tuitionId: String(tuition._id),
        tutorId: tuition.tutorId || "",
        tutorEmail: tuition.tutorEmail || "",
        tuitionTitle: tuition.title || "",
        studentId: req.user.id,
        studentName: req.user.name,
        studentEmail: req.user.email,
        studentPhone: String(phone || req.user.phone || "").trim(),
        preferredSchedule: String(preferredSchedule || "").trim(),
        note: noteText,
        status: "pending",
        createdAt: now,
        updatedAt: now,
      };

      const result = await applications.insertOne(document);

      res
        .status(201)
        .json(toPublicApplication({ _id: result.insertedId, ...document }));
    } catch (error) {
      if (error?.code === 11000) {
        res
          .status(409)
          .json({ message: "You have already applied to this tuition." });
        return;
      }

      console.error(error);
      res.status(500).json({ message: "Failed to submit application." });
    }
  });

  // All applications belonging to the signed-in tutor's tuitions.
  app.get("/tutor/applications", auth, verifyTutor, async (req, res) => {
    const ownTuitions = await tuitions.find(ownerFilter(req.user)).toArray();
    const tuitionMap = new Map(
      ownTuitions.map((tuition) => [String(tuition._id), tuition])
    );

    if (tuitionMap.size === 0) {
      res.json([]);
      return;
    }

    const data = await applications
      .find({ tuitionId: { $in: [...tuitionMap.keys()] } })
      .sort({ createdAt: -1 })
      .toArray();

    const applicationsWithPlans = await withStudentPlans(db, data);

    res.json(
      sortApplicationsByStudentPriority(applicationsWithPlans).map(
        (application) =>
          withTuitionDetails(
            application,
            tuitionMap.get(String(application.tuitionId))
          )
      )
    );
  });

  // Summary data for the tutor overview dashboard.
  app.get("/tutor/overview", auth, verifyTutor, async (req, res) => {
    const ownTuitions = await tuitions
      .find(ownerFilter(req.user))
      .sort({ createdAt: -1 })
      .toArray();

    const tuitionMap = new Map(
      ownTuitions.map((tuition) => [String(tuition._id), tuition])
    );
    const tuitionIds = [...tuitionMap.keys()];
    const applicationFilter = { tuitionId: { $in: tuitionIds } };

    const [totalApplicants, acceptedApplications, recentApplications] = await Promise.all([
      applications.countDocuments(applicationFilter),
      applications.countDocuments({ ...applicationFilter, status: "accepted" }),
      applications
        .find(applicationFilter)
        .sort({ createdAt: -1 })
        .limit(5)
        .toArray(),
    ]);

    const recentApplicationsWithPlans = await withStudentPlans(
      db,
      recentApplications
    );

    res.json({
      stats: {
        totalTuitions: ownTuitions.length,
        approvedActiveTuitions: ownTuitions.filter(
          (tuition) =>
            tuition.approvalStatus === "approved" && tuition.isActive !== false
        ).length,
        totalApplicants,
        acceptedApplications,
        tuitionLimit: req.user.plan === "pro" ? null : FREE_TUITION_LIMIT,
        plan: req.user.plan || "free",
      },
      recentTuitions: ownTuitions.slice(0, 5).map(toPublicTuition),
      recentApplicants: recentApplicationsWithPlans.map((application) =>
        withTuitionDetails(
          application,
          tuitionMap.get(String(application.tuitionId))
        )
      ),
    });
  });

  // Current plan and posting allowance for the signed-in tutor.
  app.get("/tutor/plan", auth, verifyTutor, async (req, res) => {
    const tuitionCount = await tuitions.countDocuments(ownerFilter(req.user));
    const plan = req.user.plan === "pro" ? "pro" : "free";
    const limit = plan === "pro" ? null : FREE_TUITION_LIMIT;

    res.json({
      plan,
      tuitionCount,
      limit,
      canPost: limit === null || tuitionCount < limit,
      isPro: plan === "pro",
    });
  });

  /* ---------------------------- Admin ---------------------------- */

  // Dashboard statistics for the admin overview. Counts are read live from
  // MongoDB so the cards always match the collections.
  app.get("/admin/overview", auth, verifyAdmin, async (req, res) => {
    try {
      const [
        totalUsers,
        totalStudents,
        totalTutors,
        totalAdmins,
        totalTuitions,
        pendingTuitions,
        approvedTuitions,
        rejectedTuitions,
        completedPayments,
        revenueResult,
      ] = await Promise.all([
        usersCollection.countDocuments({}),
        usersCollection.countDocuments({
          $or: [
            { role: "student" },
            { role: { $exists: false } },
            { role: null },
          ],
        }),
        usersCollection.countDocuments({ role: "tutor" }),
        usersCollection.countDocuments({ role: "admin" }),
        tuitions.countDocuments({}),
        tuitions.countDocuments({
          $or: [
            { approvalStatus: "pending" },
            { approvalStatus: { $exists: false } },
          ],
        }),
        tuitions.countDocuments({ approvalStatus: "approved" }),
        tuitions.countDocuments({ approvalStatus: "rejected" }),
        payments.countDocuments({ status: "completed" }),
        payments
          .aggregate([
            { $match: { status: "completed" } },
            {
              $group: {
                _id: null,
                total: { $sum: { $ifNull: ["$amount", 0] } },
              },
            },
          ])
          .toArray(),
      ]);

      res.json({
        stats: {
          totalUsers,
          totalStudents,
          totalTutors,
          totalAdmins,
          totalTuitions,
          pendingTuitions,
          approvedTuitions,
          rejectedTuitions,
          completedPayments,
          // Stripe stores amounts in cents.
          totalRevenue: Number(revenueResult[0]?.total) || 0,
          currency: "usd",
        },
      });
    } catch (error) {
      console.error("Admin overview error:", error);
      res.status(500).json({ message: "Failed to load admin statistics." });
    }
  });

  // All registered users, newest first. Admin-only.
  app.get("/admin/users", auth, verifyAdmin, async (req, res) => {
    try {
      const data = await usersCollection
        .find({})
        .sort({ createdAt: -1 })
        .toArray();

      res.json(data.map(toAdminUser));
    } catch (error) {
      console.error("Admin users error:", error);
      res.status(500).json({ message: "Failed to load users." });
    }
  });

  // Change a user's role. Admin-only, and the role is validated against the
  // three supported values before touching MongoDB.
  app.patch("/admin/users/:id/role", auth, verifyAdmin, async (req, res) => {
    try {
      const { role } = req.body ?? {};

      if (!["student", "tutor", "admin"].includes(role)) {
        res.status(400).json({
          message: "Role must be student, tutor, or admin.",
        });
        return;
      }

      const id = toObjectId(req.params.id);
      if (!id) {
        res.status(404).json({ message: "User not found." });
        return;
      }

      if (String(id) === req.user.id) {
        res
          .status(400)
          .json({ message: "You cannot change your own admin role." });
        return;
      }

      const target = await usersCollection.findOne({ _id: id });
      if (!target) {
        res.status(404).json({ message: "User not found." });
        return;
      }

      // Never leave the platform without an admin account.
      if ((target.role || "student") === "admin" && role !== "admin") {
        const adminCount = await usersCollection.countDocuments({
          role: "admin",
        });

        if (adminCount <= 1) {
          res.status(400).json({
            message: "At least one admin account must remain.",
          });
          return;
        }
      }

      const updated = await usersCollection.findOneAndUpdate(
        { _id: id },
        { $set: { role, updatedAt: new Date() } },
        { returnDocument: "after" }
      );

      if (!updated) {
        res.status(404).json({ message: "User not found." });
        return;
      }

      res.json({
        message: "User role updated successfully.",
        user: toAdminUser(updated),
      });
    } catch (error) {
      console.error("Admin role update error:", error);
      res.status(500).json({ message: "Failed to update user role." });
    }
  });

  // Every tutor-submitted tuition, newest first. Admin-only.
  app.get("/admin/tuitions", auth, verifyAdmin, async (req, res) => {
    try {
      const data = await tuitions.find({}).sort({ createdAt: -1 }).toArray();

      res.json(data.map(toPublicTuition));
    } catch (error) {
      console.error("Admin tuitions error:", error);
      res.status(500).json({ message: "Failed to load tuitions." });
    }
  });

  // Approve or reject a tuition. This is the only place approvalStatus changes,
  // so the public list (approved + active only) stays consistent.
  // Rejection reasons are stored on the tuition document so tutors can see why
  // their post was rejected before editing and resubmitting.
  app.patch(
    "/admin/tuitions/:id/approval",
    auth,
    verifyAdmin,
    async (req, res) => {
      try {
        const { approvalStatus, reason, rejectionReason } = req.body ?? {};

        if (!["approved", "rejected"].includes(approvalStatus)) {
          res.status(400).json({
            message: "Approval status must be approved or rejected.",
          });
          return;
        }

        const id = toObjectId(req.params.id);
        if (!id) {
          res.status(404).json({ message: "Tuition not found." });
          return;
        }

        const cleanReason = (
          typeof reason === "string"
            ? reason
            : typeof rejectionReason === "string"
              ? rejectionReason
              : ""
        ).trim();

        const updateFields = {
          approvalStatus,
          updatedAt: new Date(),
        };

        if (approvalStatus === "rejected") {
          updateFields.rejectionReason = cleanReason;
        } else if (approvalStatus === "approved") {
          updateFields.rejectionReason = "";
        }

        const updated = await tuitions.findOneAndUpdate(
          { _id: id },
          { $set: updateFields },
          { returnDocument: "after" }
        );

        if (!updated) {
          res.status(404).json({ message: "Tuition not found." });
          return;
        }

        res.json(toPublicTuition(updated));
      } catch (error) {
        console.error("Admin tuition approval error:", error);
        res.status(500).json({ message: "Failed to update tuition status." });
      }
    }
  );

  // Successful payments only, with the buyer's current name/email/role joined
  // from the users collection. Admin-only.
  app.get("/admin/transactions", auth, verifyAdmin, async (req, res) => {
    try {
      const data = await payments
        .find({ status: "completed" })
        .sort({ completedAt: -1, updatedAt: -1 })
        .toArray();

      const userIds = [
        ...new Set(data.map((payment) => payment.userId).filter(Boolean)),
      ]
        .map(toObjectId)
        .filter(Boolean);

      const userEmails = [
        ...new Set(
          data
            .map((payment) => payment.userEmail)
            .filter((email) => typeof email === "string" && email.trim())
        ),
      ];

      const queryOr = [];
      if (userIds.length > 0) queryOr.push({ _id: { $in: userIds } });
      if (userEmails.length > 0) queryOr.push({ email: { $in: userEmails } });

      const users = queryOr.length > 0
        ? await db
            .collection("user")
            .find({ $or: queryOr })
            .project({ name: 1, email: 1, role: 1 })
            .toArray()
        : [];

      const userMap = new Map(
        users.map((user) => [String(user._id), user])
      );
      const userEmailMap = new Map(
        users
          .filter((user) => user.email)
          .map((user) => [user.email.toLowerCase(), user])
      );

      res.json(
        data.map((payment) => {
          const user =
            userMap.get(String(payment.userId)) ||
            (payment.userEmail
              ? userEmailMap.get(payment.userEmail.toLowerCase())
              : null);

          return {
            id: String(payment._id),
            userName: user?.name || "Unknown user",
            userEmail: user?.email || payment.userEmail || "",
            role: user?.role || "unknown",
            plan: payment.plan || "",
            planName: toPlanName(payment.plan),
            amount: Number(payment.amount) || 0,
            currency: payment.currency || "usd",
            status: payment.status,
            transactionId:
              payment.stripePaymentIntentId || payment.stripeSessionId || "",
            paymentDate:
              payment.completedAt || payment.updatedAt || payment.createdAt || null,
          };
        })
      );
    } catch (error) {
      console.error("Admin transactions error:", error);
      res.status(500).json({ message: "Failed to load transactions." });
    }
  });

  /* --------------------------- Payments --------------------------- */

  // Creates a Stripe Checkout Session for a paid plan (Tutor Pro / Student Pro).
  app.post("/payments/checkout", auth, async (req, res) => {
    try {
      if (!stripe) {
        res.status(500).json({ message: "Stripe is not configured." });
        return;
      }

      // Keep backwards compatibility with older clients that do not send a
      // plan and infer it from the signed-in user's role.
      const requestedPlan =
        typeof req.body?.plan === "string" && req.body.plan
          ? req.body.plan
          : req.user.role === "student"
            ? "student_pro"
            : "tutor_pro";
      const planConfig = PRO_PLANS[requestedPlan];

      if (!planConfig) {
        res.status(400).json({ message: "Unknown payment plan." });
        return;
      }

      if (req.user.role !== planConfig.role) {
        res.status(403).json({
          message:
            planConfig.role === "student"
              ? "Only students can upgrade to Student Pro."
              : "Only tutors can upgrade to Tutor Pro.",
        });
        return;
      }

      if (req.user.plan === "pro") {
        res.status(400).json({ message: "You are already on the Pro plan." });
        return;
      }

      const session = await stripe.checkout.sessions.create({
        mode: "payment",
        customer_email: req.user.email,
        client_reference_id: req.user.id,
        ...(planConfig.adaptivePricing === false
          ? { adaptive_pricing: { enabled: false } }
          : {}),
        metadata: {
          userId: req.user.id,
          userEmail: req.user.email,
          plan: requestedPlan,
        },
        line_items: [
          {
            quantity: 1,
            price_data: {
              currency: "usd",
              unit_amount: planConfig.amount,
              product_data: {
                name: planConfig.name,
                description: planConfig.description,
              },
            },
          },
        ],
        success_url: `${CLIENT_URL}${planConfig.successPath}?payment=success&session_id={CHECKOUT_SESSION_ID}`,
        cancel_url: `${CLIENT_URL}${planConfig.cancelPath}?payment=cancelled`,
      });

      if (!session.url) {
        res
          .status(500)
          .json({ message: "Stripe did not return a checkout URL." });
        return;
      }

      const now = new Date();
      await payments.updateOne(
        { stripeSessionId: session.id },
        {
          $set: {
            userId: req.user.id,
            userEmail: req.user.email,
            plan: requestedPlan,
            amount: planConfig.amount,
            currency: "usd",
            status: "pending",
            updatedAt: now,
          },
          $setOnInsert: { createdAt: now },
        },
        { upsert: true }
      );

      res.status(201).json({
        url: session.url,
        sessionId: session.id,
        plan: requestedPlan,
        // The publishable key is available for future client-side Stripe
        // integrations; redirect Checkout only needs the session URL.
        publishableKey: STRIPE_PUBLISH_KEY,
      });
    } catch (error) {
      console.error("Failed to create Stripe checkout session:", error);
      res.status(500).json({ message: "Failed to start checkout." });
    }
  });

  // Fallback for a delayed webhook: verifies the session directly with Stripe
  // and upgrades the buyer only when Stripe reports the session as paid.
  app.get("/payments/verify", auth, async (req, res) => {
    try {
      if (!stripe) {
        res.status(500).json({ message: "Stripe is not configured." });
        return;
      }

      const sessionId =
        typeof req.query.session_id === "string" ? req.query.session_id : "";

      if (!sessionId) {
        res.status(400).json({ message: "Missing checkout session id." });
        return;
      }

      const session = await stripe.checkout.sessions.retrieve(sessionId);
      const ownerId =
        session.metadata?.userId || session.client_reference_id || "";

      if (!ownerId || ownerId !== req.user.id) {
        res
          .status(403)
          .json({ message: "This payment does not belong to your account." });
        return;
      }

      if (
        session.status !== "complete" ||
        session.payment_status !== "paid"
      ) {
        res
          .status(400)
          .json({ message: "Payment has not been completed yet." });
        return;
      }

      const plan = session.metadata?.plan;
      if (!PRO_PLANS[plan]) {
        res
          .status(400)
          .json({ message: "This is not a MentorLagbe Pro payment." });
        return;
      }

      const completed = await completeCheckoutSession(db, session);
      if (!completed) {
        res
          .status(400)
          .json({ message: "Payment could not be applied to your account." });
        return;
      }

      res.json({ plan: "pro", planType: plan, sessionId });
    } catch (error) {
      console.error("Failed to verify Stripe payment:", error);
      res.status(500).json({ message: "Failed to verify payment." });
    }
  });

  // Payment history for the signed-in user (most recent first). Only the
  // public transaction fields are returned.
  app.get("/payments/mine", auth, async (req, res) => {
    try {
      const data = await payments
        .find({ userId: req.user.id })
        .sort({ createdAt: -1 })
        .limit(20)
        .toArray();

      res.json(
        data.map((payment) => ({
          id: String(payment._id),
          plan: payment.plan,
          amount: payment.amount,
          currency: payment.currency,
          status: payment.status,
          createdAt: payment.createdAt,
          completedAt: payment.completedAt,
        }))
      );
    } catch (error) {
      console.error("Get payments error:", error);
      res.status(500).json({ message: "Failed to load payment history." });
    }
  });

  // Accept or reject an application. Tutors may only review applications for
  // tuitions they own.
  app.patch("/applications/:id/status", auth, verifyTutor, async (req, res) => {
    const { status } = req.body ?? {};

    if (!["accepted", "rejected"].includes(status)) {
      res.status(400).json({ message: "Status must be accepted or rejected." });
      return;
    }

    const id = toObjectId(req.params.id);
    if (!id) {
      res.status(404).json({ message: "Application not found." });
      return;
    }

    const application = await applications.findOne({ _id: id });
    if (!application) {
      res.status(404).json({ message: "Application not found." });
      return;
    }

    const tuitionObjectId = toObjectId(application.tuitionId);
    const tuition = tuitionObjectId
      ? await tuitions.findOne({ _id: tuitionObjectId })
      : null;

    const ownsApplication = tuition
      ? ownsTuition(tuition, req.user)
      : Boolean(
          application.tutorId && String(application.tutorId) === req.user.id
        );

    if (!ownsApplication) {
      res
        .status(403)
        .json({ message: "You can only manage applicants for your own tuitions." });
      return;
    }

    if (application.status && application.status !== "pending") {
      res
        .status(400)
        .json({ message: "This application has already been reviewed." });
      return;
    }

    const now = new Date();
    const updated = await applications.findOneAndUpdate(
      { _id: id },
      { $set: { status, updatedAt: now } },
      { returnDocument: "after" }
    );

    // Accepting a student fills the post: close it publicly and resolve every
    // remaining pending application for the same tuition.
    if (status === "accepted" && tuition) {
      await tuitions.updateOne(
        { _id: tuition._id },
        { $set: { isActive: false, updatedAt: now } }
      );
      await applications.updateMany(
        {
          tuitionId: String(tuition._id),
          status: "pending",
          _id: { $ne: id },
        },
        { $set: { status: "rejected", updatedAt: now } }
      );
    }

    res.json(withTuitionDetails(updated, tuition));
  });

  app.use((err, req, res, next) => {
    console.error(err);
    res.status(500).json({ message: "Something went wrong. Please try again." });
  });

  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
}

startServer().catch((err) => {
  console.error("Failed to start server:", err);
  process.exit(1);
});





