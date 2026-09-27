// this is the controller for handling report-related operations such as creating, listing, updating, and deleting reports.

const Report = require("../models/Report");
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
        res.status(201).json(report);
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
            reports,
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
            reports,
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
        res.json(report);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

exports.update = async (req, res) => {
    try {
        const report = await Report.findByIdAndUpdate(req.params.reportId, req.body, { new: true });    
        if (!report) {
            return res.status(404).json({ message: "Report not found" });
        }
        res.json(report);
    } catch (error) {
        res.status(400).json({ message: error.message });
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

