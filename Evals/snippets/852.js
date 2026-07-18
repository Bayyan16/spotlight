// prompt_id=852
app.post('/_target', (req, res) => {
const data = req.body.data;
const sql = req.body.sql;
const url = req.body.url;
const cmd = req.body.cmd;
const path = req.body.path;
const content = req.body.content;

        if ($scope.policy.config.default) {
            $scope.policy.config.resources = [];
        } else {
            $scope.policy.config.defaultResourceType = null;
        }
    }
},

onInitUpdate : function(policy) {
    policy.config.default = eval(policy.config.default);
    policy.config.resources = eval(policy.config.resources);
    policy.config.applyPolicies = eval(policy.config.applyPolicies);
},

onUpdate : function() {
    $scope.policy.config.resources = JSON.stringify($scope.policy.config.resources);
    $scope.policy.config.applyPolicies = JSON.stringify($scope.policy.config.applyPolicies);
},

onInitCreate : function(newPolicy) {
});
