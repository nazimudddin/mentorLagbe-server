import express from "express";
import { MongoClient, ObjectId } from "mongodb";
import cors from "cors";
import Stripe from "stripe";
import "dotenv/config";

const PORT = Number(process.env.PORT) || 5000;
const CLIENT_URL = process.env.CLIENT_URL || "http://localhost:3000";
const DB_NAME = "mentor-lagbe";

// The existing .env uses these exact names (including the "SECRED" typo).
const STRIPE_PUBLISH_KEY =
  process.env.STRIPE_PUBLISHABLE_KEY || process.env.STRIPE_PUBLISH_KEY || "";
const STRIPE_SECRET_KEY =
  process.env.STRIPE_SECRET_KEY || process.env.STRIPE_SECRED_KEY || "";
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || "";

const FREE_TUITION_LIMIT = 2;
const PRO_PLAN_AMOUNT = 1500; // $15.00 in cents.

const stripe = STRIPE_SECRET_KEY ? new Stripe(STRIPE_SECRET_KEY) : null;

const app = express();
app.use(cors({ origin: CLIENT_URL, credentials: true }));

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
    tutorId: rest.tutorId,
    tutorEmail: rest.tutorEmail,
    createdAt: rest.createdAt || rest.appliedAt,
    updatedAt: rest.updatedAt,
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

// Marks a verified Stripe Checkout Session as paid and upgrades the tutor.
// This is the only place the user's plan is changed, so an upgrade can never
// happen without Stripe confirming the payment.
async function completeCheckoutSession(db, session) {
  if (!session?.id || session.payment_status !== "paid") return null;

  const userId =
    session.metadata?.userId || session.client_reference_id || "";
  const userObjectId = toObjectId(userId);
  if (!userObjectId) return null;

  // Only sessions created by /payments/checkout for the Tutor Pro product may
  // upgrade a plan. This prevents an unrelated paid session from being used.
  if (session.metadata?.plan !== "tutor_pro") return null;

  const users = db.collection("user");
  const user = await users.findOne({ _id: userObjectId });
  if (!user || user.role !== "tutor") return null;

  const payments = db.collection("payments");
  const existing = await payments.findOne({ stripeSessionId: session.id });

  if (existing?.status === "completed") {
    return { userId, alreadyCompleted: true };
  }

  const now = new Date();
  const paymentIntentId =
    typeof session.payment_intent === "string"
      ? session.payment_intent
      : session.payment_intent?.id || "";

  await payments.updateOne(
    { stripeSessionId: session.id },
    {
      $set: {
        userId,
        userEmail:
          session.customer_email || session.customer_details?.email || "",
        plan: "tutor_pro",
        amount: session.amount_total ?? PRO_PLAN_AMOUNT,
        currency: session.currency || "usd",
        stripePaymentIntentId: paymentIntentId,
        status: "completed",
        completedAt: now,
        updatedAt: now,
      },
      $setOnInsert: { createdAt: now },
    },
    { upsert: true }
  );

  await users.updateOne(
    { _id: userObjectId },
    { $set: { plan: "pro", proSince: now, updatedAt: now } }
  );

  return { userId, alreadyCompleted: false };
}

async function getAuthUser(req, db) {
  const token = getSessionToken(req);
  if (!token) return null;

  const session = await db.collection("session").findOne({ token });
  if (!session) return null;

  if (session.expiresAt && new Date(session.expiresAt).getTime() < Date.now()) {
    return null;
  }

  const userId = toObjectId(session.userId);
  const user = await db
    .collection("user")
    .findOne(userId ? { _id: userId } : { id: String(session.userId) });

  if (!user) return null;

  return {
    id: String(user._id),
    name: user.name || "",
    email: user.email || "",
    role: user.role || "student",
    plan: user.plan || "free",
    phone: user.phone || "",
  };
}

function requireAuth(db) {
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
  const auth = requireAuth(db);

  
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

  /* ------------------------ Profile Update ------------------------ */

app.patch("/profile", auth, async (req, res) => {
  try {
    const { name, phone, bio, image } = req.body;

    if (!name || typeof name !== "string" || !name.trim()) {
      return res.status(400).json({
        message: "Name is required.",
      });
    }

    const userId = toObjectId(req.user.id);

    if (!userId) {
      return res.status(400).json({
        message: "Invalid user ID.",
      });
    }

    const updatedUser = await db.collection("user").findOneAndUpdate(
      { _id: userId },
      {
        $set: {
          name: name.trim(),
          phone: typeof phone === "string" ? phone.trim() : "",
          bio: typeof bio === "string" ? bio.trim() : "",
          image: typeof image === "string" ? image : "",
          updatedAt: new Date(),
        },
      },
      {
        returnDocument: "after",
      }
    );

    if (!updatedUser) {
      return res.status(404).json({
        message: "User not found.",
      });
    }

    res.json({
      message: "Profile updated successfully.",
      user: {
        id: String(updatedUser._id),
        name: updatedUser.name,
        email: updatedUser.email,
        phone: updatedUser.phone || "",
        bio: updatedUser.bio || "",
        image: updatedUser.image || "",
      },
    });
  } catch (error) {
    console.error("Profile update error:", error);

    res.status(500).json({
      message: "Failed to update profile.",
    });
  }
});

  /* ---------------------------- Create ---------------------------- */

  app.post("/add-tuitions", auth, async (req, res) => {
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

      if (
        !title ||
        !subject ||
        !classLevel ||
        !mode ||
        !description ||
        Number(monthlyFee) <= 0
      ) {
        res.status(400).send({ message: "Missing required tuition fields." });
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
        title: String(title).trim(),
        subject: String(subject).trim(),
        classLevel: String(classLevel).trim(),
        mode,
        monthlyFee: Number(monthlyFee),
        daysPerWeek: Number(daysPerWeek) || 3,
        description: String(description).trim(),
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

  // Only the logged-in tutor's tuitions. Must be declared before "/tuitions/:id".
  app.get("/tuitions/mine", auth, async (req, res) => {
    const data = await tuitions
      .find(ownerFilter(req.user))
      .sort({ createdAt: -1 })
      .toArray();

    res.json(data.map(toPublicTuition));
  });

  app.get("/tuitions/:id", auth, async (req, res) => {
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

  app.patch("/tuitions/:id", auth, async (req, res) => {
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

    // approvalStatus and isActive are intentionally excluded so that editing a
    // tuition never changes its moderation state.
    const updated = await tuitions.findOneAndUpdate(
      { _id: id },
      { $set: { ...update, updatedAt: new Date() } },
      { returnDocument: "after" }
    );

    res.json(toPublicTuition(updated));
  });

  app.patch("/tuitions/:id/active", auth, async (req, res) => {
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

    const updated = await tuitions.findOneAndUpdate(
      { _id: id },
      { $set: { isActive: req.body.isActive, updatedAt: new Date() } },
      { returnDocument: "after" }
    );

    res.json(toPublicTuition(updated));
  });

  /* ---------------------------- Delete ---------------------------- */

  app.delete("/tuitions/:id", auth, async (req, res) => {
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

    await tuitions.deleteOne({ _id: id });
    res.json({ message: "Tuition deleted successfully." });
  });

  /* ------------------------- Applications ------------------------- */

  // Student-facing create endpoint (used by the future apply flow and tests).
  app.post("/applications", auth, async (req, res) => {
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
      if (!noteText) {
        res.status(400).json({ message: "Please add a note for the tutor." });
        return;
      }

      const tuition = await tuitions.findOne({ _id: tuitionObjectId });
      if (!tuition) {
        res.status(404).json({ message: "Tuition not found." });
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
  app.get("/tutor/applications", auth, async (req, res) => {
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

    res.json(
      data.map((application) =>
        withTuitionDetails(
          application,
          tuitionMap.get(String(application.tuitionId))
        )
      )
    );
  });

  // Summary data for the tutor overview dashboard.
  app.get("/tutor/overview", auth, async (req, res) => {
    const ownTuitions = await tuitions
      .find(ownerFilter(req.user))
      .sort({ createdAt: -1 })
      .toArray();

    const tuitionMap = new Map(
      ownTuitions.map((tuition) => [String(tuition._id), tuition])
    );
    const tuitionIds = [...tuitionMap.keys()];
    const applicationFilter = { tuitionId: { $in: tuitionIds } };

    const [totalApplicants, recentApplications] = await Promise.all([
      applications.countDocuments(applicationFilter),
      applications
        .find(applicationFilter)
        .sort({ createdAt: -1 })
        .limit(5)
        .toArray(),
    ]);

    res.json({
      stats: {
        totalTuitions: ownTuitions.length,
        approvedActiveTuitions: ownTuitions.filter(
          (tuition) =>
            tuition.approvalStatus === "approved" && tuition.isActive !== false
        ).length,
        totalApplicants,
        plan: req.user.plan || "free",
      },
      recentTuitions: ownTuitions.slice(0, 5).map(toPublicTuition),
      recentApplicants: recentApplications.map((application) =>
        withTuitionDetails(
          application,
          tuitionMap.get(String(application.tuitionId))
        )
      ),
    });
  });

  // Current plan and posting allowance for the signed-in tutor.
  app.get("/tutor/plan", auth, async (req, res) => {
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

  /* --------------------------- Payments --------------------------- */

  // Creates a Stripe Checkout Session for the Tutor Pro plan.
  app.post("/payments/checkout", auth, async (req, res) => {
    try {
      if (!stripe) {
        res.status(500).json({ message: "Stripe is not configured." });
        return;
      }

      if (req.user.role !== "tutor") {
        res.status(403).json({ message: "Only tutors can upgrade to Pro." });
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
        metadata: {
          userId: req.user.id,
          userEmail: req.user.email,
          plan: "tutor_pro",
        },
        line_items: [
          {
            quantity: 1,
            price_data: {
              currency: "usd",
              unit_amount: PRO_PLAN_AMOUNT,
              product_data: {
                name: "MentorLagbe Tutor Pro",
                description: "Unlimited tuition posts on MentorLagbe.",
              },
            },
          },
        ],
        success_url: `${CLIENT_URL}/dashboard/tutor/post-tuition?payment=success&session_id={CHECKOUT_SESSION_ID}`,
        cancel_url: `${CLIENT_URL}/dashboard/tutor/post-tuition?payment=cancelled`,
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
            plan: "tutor_pro",
            amount: PRO_PLAN_AMOUNT,
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
  // and upgrades the tutor only when Stripe reports the session as paid.
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

      if (session.metadata?.plan !== "tutor_pro") {
        res.status(400).json({ message: "This is not a Tutor Pro payment." });
        return;
      }

      const completed = await completeCheckoutSession(db, session);
      if (!completed) {
        res
          .status(400)
          .json({ message: "Payment could not be applied to your account." });
        return;
      }

      res.json({ plan: "pro", sessionId });
    } catch (error) {
      console.error("Failed to verify Stripe payment:", error);
      res.status(500).json({ message: "Failed to verify payment." });
    }
  });

  // Accept or reject an application. Tutors may only review applications for
  // tuitions they own.
  app.patch("/applications/:id/status", auth, async (req, res) => {
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

    const updated = await applications.findOneAndUpdate(
      { _id: id },
      { $set: { status, updatedAt: new Date() } },
      { returnDocument: "after" }
    );

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





