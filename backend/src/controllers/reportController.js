// this is the controller for handling report-related operations such as creating, listing, updating, and deleting reports.

const Report = require("../models/Report");

const {
  serializeReport,
  serializeReports,
} = require("../utils/reportSerializer");


exports.create = async (req, res) => {
    try { 
        const attachments = [];
        if (req.files && req.files.length > 0) {
            req.files.forEach(file => {
                attachments.push({
                    url: file.path, // Cloudinary URL
                    type: file.mimetype,
                });
            });
        }

        // Remove any attachments keys from body (multer may add attachments, attachments[0], etc.)
        const body = {};
        for (const key of Object.keys(req.body)) {
            if (!key.startsWith("attachments")) {
                body[key] = req.body[key];
            }
        }
        const report = new Report({
            ...body,
            reportedBy: req.user._id,
            attachments
        });
        await report.save();

        res.status(201).json(
            serializeReport(report, {
                viewer: req.user,
                req,
            })
            );

    } catch (error) {
        res.status(400).json({ message: error.message });
    }
};


exports.listMine = async (req, res) => {
    try {
        const { page = 1, limit = 10 } = req.query;
        const query = {
            reportedBy: req.user._id,
            isDeleted: { $ne: true },
        };

        const reports = await Report.find(query)
            .limit(limit * 1)
            .skip((page - 1) * limit)
            .sort({ createdAt: -1 });

        const total = await Report.countDocuments(query);

        res.json({
            reports: serializeReports(reports, {
                viewer: req.user,
                req,
            }),
            totalPages: Math.ceil(total / limit),
            currentPage: page,
            total
        });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

exports.list = async (req, res) => {
    try {
        const { page = 1, limit = 10, reportType, severity, status } = req.query;
        const query = {
            isDeleted: { $ne: true },
        };
        if (reportType) query.reportType = reportType;
        if (severity) query.severity = severity;
        if (status) query.status = status;

        const reports = await Report.find(query)
            .populate("reportedBy", "name email")
            .limit(limit * 1)
            .skip((page - 1) * limit)
            .sort({ createdAt: -1 });
        
        const total = await Report.countDocuments(query);
        
        res.json({
            reports: serializeReports(reports, {
                viewer: req.user,
                req,
            }),
            totalPages: Math.ceil(total / limit),
            currentPage: page,
            total
        });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

exports.getById = async (req, res) => {
    try {
        const report = await Report.findOne({
            _id: req.params.reportId,
            isDeleted: { $ne: true },
        }).populate("reportedBy", "name email");
        if (!report) {
            return res.status(404).json({ message: "Report not found" });
        }
                res.json(
            serializeReport(report, {
                viewer: req.user,
                req,
            })
        );
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};


const OWNER_UPDATE_FIELDS = new Set([
    "title",
    "description",
    "severity",
]);

const WORKFLOW_UPDATE_FIELDS = new Set([
    "status",
]);

const ELEVATED_UPDATE_ROLES = new Set([
    "OFFICER",
    "SYSTEM_ADMIN",
]);

exports.update = async (req, res) => {
    try {
        const report = await Report.findOne({
            _id: req.params.reportId,
            isDeleted: { $ne: true },
        });

        if (!report) {
            return res.status(404).json({ message: "Report not found" });
        }

        const ownerId =
            report.reportedBy?._id?.toString?.() ||
            report.reportedBy?.toString?.();

        const callerId = req.user._id.toString();
        const hasElevatedRole = ELEVATED_UPDATE_ROLES.has(req.user.role);
        const isOwner = ownerId === callerId;

        if (!hasElevatedRole && !isOwner) {
            return res.status(403).json({
                message: "You are not authorized to update this report",
            });
        }

        const allowedFields = hasElevatedRole
            ? WORKFLOW_UPDATE_FIELDS
            : OWNER_UPDATE_FIELDS;

        const requestedFields = Object.keys(req.body || {});
        const hasDisallowedField = requestedFields.some(
            (field) => !allowedFields.has(field)
        );

        if (requestedFields.length === 0 || hasDisallowedField) {
            return res.status(400).json({
                message: "One or more fields cannot be updated by this role",
            });
        }

        requestedFields.forEach((field) => {
            report[field] = req.body[field];
        });

        await report.save();

        res.status(200).json(
            serializeReport(report, {
                viewer: req.user,
                req,
            })
            );
    } catch (error) {
        if (error.name === "ValidationError") {
            return res.status(400).json({ message: error.message });
        }

        res.status(500).json({ message: "Unable to update report" });
    }
};


exports.remove = async (req, res) => {
    try {
        const report = await Report.findOneAndUpdate(
            {
                _id: req.params.reportId,
                isDeleted: { $ne: true },
            },
            {
                $set: {
                    isDeleted: true,
                    deletedBy: req.user._id,
                    deletedAt: new Date(),
                },
            },
            {
                returnDocument: "after",
                runValidators: true,
            }
        );

        if (!report) {
            return res.status(404).json({ message: "Report not found" });
        }

        console.info(
            `[Security] Report soft-deleted: ${report._id} by ${req.user.email} (${req.user.role})`
        );

        res.status(200).json({
            message: "Report deleted successfully",
            report: {
                _id: report._id,
                isDeleted: report.isDeleted,
                deletedBy: report.deletedBy,
                deletedAt: report.deletedAt,
            },
        });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

