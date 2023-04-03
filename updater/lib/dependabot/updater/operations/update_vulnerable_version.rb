# frozen_string_literal: true

# This class implements our strategy for updating a single, insecure dependency
# to a secure version. We attempt to make the smallest version update possible,
# i.e. semver patch-level increase is preferred over minor-level increase.
module Dependabot
  class Updater
    module Operations
      class UpdateVulnerableVersion # rubocop:disable Metrics/ClassLength
        def self.applies_to?(job:)
          return false if job.updating_a_pull_request?
          # If we haven't been given data for the vulnerable dependency,
          # this strategy cannot act.
          return false if job.dependencies&.none?

          job.security_updates_only?
        end

        def initialize(service:, job:, dependency_snapshot:, error_handler:)
          @service = service
          @job = job
          @dependency_snapshot = dependency_snapshot
          @error_handler = error_handler
          # TODO: Collect @created_pull_requests on the Job object?
          @created_pull_requests = []
        end

        # TODO: We currently tolerate multiple dependencies for this operation
        #       but in reality, we only expect a single dependency per job.
        #
        # Changing this contract now without some safety catches introduces
        # risk, so we'll maintain the interface as-is for now, but this is
        # something we should make much more intentional in future.
        def perform
          Dependabot.logger.info("Starting update job for #{job.source.repo}")
          dependencies.each { |dep| check_and_create_pr_with_error_handling(dep) }
        end

        private

        attr_reader :job,
                    :service,
                    :dependency_snapshot,
                    :error_handler,
                    :created_pull_requests

        def dependencies
          dependency_snapshot.job_dependencies
        end

        def check_and_create_pr_with_error_handling(dependency)
          check_and_create_pull_request(dependency)
        rescue Dependabot::InconsistentRegistryResponse => e
          error_handler.log_error(
            dependency: dependency,
            error: e,
            error_type: "inconsistent_registry_response",
            error_detail: e.message
          )
        rescue StandardError => e
          error_handler.handle_dependabot_error(error: e, dependency: dependency)
        end

        # rubocop:disable Metrics/AbcSize
        # rubocop:disable Metrics/CyclomaticComplexity
        # rubocop:disable Metrics/PerceivedComplexity
        # rubocop:disable Metrics/MethodLength
        def check_and_create_pull_request(dependency)
          checker = update_checker_for(dependency, raise_on_ignored: raise_on_ignored?(dependency))

          log_checking_for_update(dependency)

          Dependabot.logger.info("Latest version is #{checker.latest_version}")

          unless checker.vulnerable?
            # The current dependency isn't vulnerable if the version is correct and
            # can be matched against the advisories affected versions
            if checker.version_class.correct?(checker.dependency.version)
              return record_security_update_not_needed_error(checker)
            end

            return record_dependency_file_not_supported_error(checker)
          end

          return record_security_update_ignored(checker) unless job.allowed_update?(dependency)

          # The current version is still vulnerable and  Dependabot can't find a
          # published or compatible non-vulnerable version, this can happen if the
          # fixed version hasn't been published yet or the published version isn't
          # compatible with the current enviroment (e.g. python version) or
          # version (uses a different version suffix for gradle/maven)
          return record_security_update_not_found(checker) if checker.up_to_date?

          if pr_exists_for_latest_version?(checker)
            Dependabot.logger.info(
              "Pull request already exists for #{checker.dependency.name} " \
              "with latest version #{checker.latest_version}"
            )
            return record_pull_request_exists_for_latest_version(checker)
          end

          requirements_to_unlock = requirements_to_unlock(checker)
          log_requirements_for_update(requirements_to_unlock, checker)

          return record_security_update_not_possible_error(checker) if requirements_to_unlock == :update_not_possible

          updated_deps = checker.updated_dependencies(
            requirements_to_unlock: requirements_to_unlock
          )

          # Prevent updates that don't end up fixing any security advisories,
          # blocking any updates where dependabot-core updates to a vulnerable
          # version. This happens for npm/yarn subdendencies where Dependabot has no
          # control over the target version. Related issue:
          # https://github.com/github/dependabot-api/issues/905
          return record_security_update_not_possible_error(checker) if updated_deps.none? { |d| job.security_fix?(d) }

          if (existing_pr = existing_pull_request(updated_deps))
            # Create a update job error to prevent dependabot-api from creating a
            # update_not_possible error, this is likely caused by a update job retry
            # so should be invisible to users (as the first job completed with a pull
            # request)
            record_pull_request_exists_for_security_update(existing_pr)

            deps = existing_pr.map do |dep|
              if dep.fetch("dependency-removed", false)
                "#{dep.fetch('dependency-name')}@removed"
              else
                "#{dep.fetch('dependency-name')}@#{dep.fetch('dependency-version')}"
              end
            end

            return Dependabot.logger.info(
              "Pull request already exists for #{deps.join(', ')}"
            )
          end

          if peer_dependency_should_update_instead?(checker.dependency.name, updated_deps)
            return Dependabot.logger.info(
              "No update possible for #{dependency.name} #{dependency.version} " \
              "(peer dependency can be updated)"
            )
          end

          updated_files = generate_dependency_files_for(updated_deps)
          updated_deps = updated_deps.reject do |d|
            next false if d.name == checker.dependency.name
            next true if d.top_level? && d.requirements == d.previous_requirements

            d.version == d.previous_version
          end
          create_pull_request(updated_deps, updated_files)
        rescue Dependabot::AllVersionsIgnored
          Dependabot.logger.info("All updates for #{dependency.name} were ignored")
          # Report this error to the backend to create an update job error
          raise
        end
        # rubocop:enable Metrics/MethodLength
        # rubocop:enable Metrics/AbcSize
        # rubocop:enable Metrics/CyclomaticComplexity
        # rubocop:enable Metrics/PerceivedComplexity

        def raise_on_ignored?(dependency)
          job.security_updates_only? || ignore_conditions_for(dependency).any?
        end

        def update_checker_for(dependency, raise_on_ignored:)
          Dependabot::UpdateCheckers.for_package_manager(job.package_manager).new(
            dependency: dependency,
            dependency_files: dependency_snapshot.dependency_files,
            repo_contents_path: job.repo_contents_path,
            credentials: job.credentials,
            ignored_versions: ignore_conditions_for(dependency),
            security_advisories: job.security_advisories_for(dependency),
            raise_on_ignored: raise_on_ignored,
            requirements_update_strategy: job.requirements_update_strategy,
            options: job.experiments
          )
        end

        def file_updater_for(dependencies)
          Dependabot::FileUpdaters.for_package_manager(job.package_manager).new(
            dependencies: dependencies,
            dependency_files: dependency_snapshot.dependency_files,
            repo_contents_path: job.repo_contents_path,
            credentials: job.credentials,
            options: job.experiments
          )
        end

        def ignore_conditions_for(dep)
          update_config_ignored_versions(job.ignore_conditions, dep)
        end

        def update_config_ignored_versions(ignore_conditions, dep)
          ignore_conditions = ignore_conditions.map do |ic|
            Dependabot::Config::IgnoreCondition.new(
              dependency_name: ic["dependency-name"],
              versions: [ic["version-requirement"]].compact,
              update_types: ic["update-types"]
            )
          end
          Dependabot::Config::UpdateConfig.
            new(ignore_conditions: ignore_conditions).
            ignored_versions_for(dep, security_updates_only: job.security_updates_only?)
        end

        def name_match?(name1, name2)
          WildcardMatcher.match?(
            job.name_normaliser.call(name1),
            job.name_normaliser.call(name2)
          )
        end

        def log_checking_for_update(dependency)
          Dependabot.logger.info(
            "Checking if #{dependency.name} #{dependency.version} needs updating"
          )
          log_ignore_conditions(dependency)
        end

        def log_ignore_conditions(dep)
          conditions = job.ignore_conditions.
                       select { |ic| name_match?(ic["dependency-name"], dep.name) }
          return if conditions.empty?

          Dependabot.logger.info("Ignored versions:")
          conditions.each do |ic|
            unless ic["version-requirement"].nil?
              Dependabot.logger.info("  #{ic['version-requirement']} - from #{ic['source']}")
            end

            ic["update-types"]&.each do |update_type|
              msg = "  #{update_type} - from #{ic['source']}"
              msg += " (doesn't apply to security update)" if job.security_updates_only?
              Dependabot.logger.info(msg)
            end
          end
        end

        def pr_exists_for_latest_version?(checker)
          latest_version = checker.latest_version&.to_s
          return false if latest_version.nil?

          job.existing_pull_requests.
            select { |pr| pr.count == 1 }.
            map(&:first).
            select { |pr| pr.fetch("dependency-name") == checker.dependency.name }.
            any? { |pr| pr.fetch("dependency-version", nil) == latest_version }
        end

        def record_security_update_not_needed_error(checker)
          Dependabot.logger.info(
            "no security update needed as #{checker.dependency.name} " \
            "is no longer vulnerable"
          )

          service.record_update_job_error(
            error_type: "security_update_not_needed",
            error_details: {
              "dependency-name": checker.dependency.name
            }
          )
        end

        def record_security_update_ignored(checker)
          Dependabot.logger.info(
            "Dependabot cannot update to the required version as all versions " \
            "were ignored for #{checker.dependency.name}"
          )

          service.record_update_job_error(
            error_type: "all_versions_ignored",
            error_details: {
              "dependency-name": checker.dependency.name
            }
          )
        end

        def record_dependency_file_not_supported_error(checker)
          Dependabot.logger.info(
            "Dependabot can't update vulnerable dependencies for projects " \
            "without a lockfile or pinned version requirement as the currently " \
            "installed version of #{checker.dependency.name} isn't known."
          )

          service.record_update_job_error(
            error_type: "dependency_file_not_supported",
            error_details: {
              "dependency-name": checker.dependency.name
            }
          )
        end

        def record_security_update_not_possible_error(checker)
          latest_allowed_version =
            (checker.lowest_resolvable_security_fix_version ||
             checker.dependency.version)&.to_s
          lowest_non_vulnerable_version =
            checker.lowest_security_fix_version&.to_s
          conflicting_dependencies = checker.conflicting_dependencies

          Dependabot.logger.info(
            security_update_not_possible_message(checker, latest_allowed_version,
                                                 conflicting_dependencies)
          )
          Dependabot.logger.info(earliest_fixed_version_message(lowest_non_vulnerable_version))

          service.record_update_job_error(
            error_type: "security_update_not_possible",
            error_details: {
              "dependency-name": checker.dependency.name,
              "latest-resolvable-version": latest_allowed_version,
              "lowest-non-vulnerable-version": lowest_non_vulnerable_version,
              "conflicting-dependencies": conflicting_dependencies
            }
          )
        end

        def record_security_update_not_found(checker)
          Dependabot.logger.info(
            "Dependabot can't find a published or compatible non-vulnerable " \
            "version for #{checker.dependency.name}. " \
            "The latest available version is #{checker.dependency.version}"
          )

          service.record_update_job_error(
            error_type: "security_update_not_found",
            error_details: {
              "dependency-name": checker.dependency.name,
              "dependency-version": checker.dependency.version
            },
            dependency: checker.dependency
          )
        end

        def record_pull_request_exists_for_latest_version(checker)
          service.record_update_job_error(
            error_type: "pull_request_exists_for_latest_version",
            error_details: {
              "dependency-name": checker.dependency.name,
              "dependency-version": checker.latest_version&.to_s
            },
            dependency: checker.dependency
          )
        end

        def record_pull_request_exists_for_security_update(existing_pull_request)
          updated_dependencies = existing_pull_request.map do |dep|
            {
              "dependency-name": dep.fetch("dependency-name"),
              "dependency-version": dep.fetch("dependency-version", nil),
              "dependency-removed": dep.fetch("dependency-removed", nil)
            }.compact
          end

          service.record_update_job_error(
            error_type: "pull_request_exists_for_security_update",
            error_details: {
              "updated-dependencies": updated_dependencies
            }
          )
        end

        def earliest_fixed_version_message(lowest_non_vulnerable_version)
          if lowest_non_vulnerable_version
            "The earliest fixed version is #{lowest_non_vulnerable_version}."
          else
            "Dependabot could not find a non-vulnerable version"
          end
        end

        def security_update_not_possible_message(checker, latest_allowed_version,
                                                 conflicting_dependencies)
          if conflicting_dependencies.any?
            dep_messages = conflicting_dependencies.map do |dep|
              "  #{dep['explanation']}"
            end.join("\n")

            dependencies_pluralized =
              conflicting_dependencies.count > 1 ? "dependencies" : "dependency"

            "The latest possible version that can be installed is " \
              "#{latest_allowed_version} because of the following " \
              "conflicting #{dependencies_pluralized}:\n\n#{dep_messages}"
          else
            "The latest possible version of #{checker.dependency.name} that can " \
              "be installed is #{latest_allowed_version}"
          end
        end

        def requirements_to_unlock(checker)
          if job.lockfile_only? || !checker.requirements_unlocked_or_can_be?
            if checker.can_update?(requirements_to_unlock: :none) then :none
            else
              :update_not_possible
            end
          elsif checker.can_update?(requirements_to_unlock: :own) then :own
          elsif checker.can_update?(requirements_to_unlock: :all) then :all
          else
            :update_not_possible
          end
        end

        def log_up_to_date(dependency)
          Dependabot.logger.info(
            "No update needed for #{dependency.name} #{dependency.version}"
          )
        end

        def log_requirements_for_update(requirements_to_unlock, checker)
          Dependabot.logger.info("Requirements to unlock #{requirements_to_unlock}")

          return unless checker.respond_to?(:requirements_update_strategy)

          Dependabot.logger.info(
            "Requirements update strategy #{checker.requirements_update_strategy}"
          )
        end

        def existing_pull_request(updated_dependencies)
          new_pr_set = Set.new(
            updated_dependencies.map do |dep|
              {
                "dependency-name" => dep.name,
                "dependency-version" => dep.version,
                "dependency-removed" => dep.removed? ? true : nil
              }.compact
            end
          )

          job.existing_pull_requests.find { |pr| Set.new(pr) == new_pr_set } ||
            created_pull_requests.find { |pr| Set.new(pr) == new_pr_set }
        end

        # If a version update for a peer dependency is possible we should
        # defer to the PR that will be created for it to avoid duplicate PRs.
        def peer_dependency_should_update_instead?(dependency_name, updated_deps)
          # This doesn't apply to security updates as we can't rely on the
          # peer dependency getting updated.
          return false if job.security_updates_only?

          updated_deps.
            reject { |dep| dep.name == dependency_name }.
            any? do |dep|
              next true if existing_pull_request([dep])

              original_peer_dep = ::Dependabot::Dependency.new(
                name: dep.name,
                version: dep.previous_version,
                requirements: dep.previous_requirements,
                package_manager: dep.package_manager
              )
              update_checker_for(original_peer_dep, raise_on_ignored: false).
                can_update?(requirements_to_unlock: :own)
            end
        end

        def generate_dependency_files_for(updated_dependencies)
          if updated_dependencies.count == 1
            updated_dependency = updated_dependencies.first
            Dependabot.logger.info("Updating #{updated_dependency.name} from " \
                                   "#{updated_dependency.previous_version} to " \
                                   "#{updated_dependency.version}")
          else
            dependency_names = updated_dependencies.map(&:name)
            Dependabot.logger.info("Updating #{dependency_names.join(', ')}")
          end

          # Ignore dependencies that are tagged as information_only. These will be
          # updated indirectly as a result of a parent dependency update and are
          # only included here to be included in the PR info.
          deps_to_update = updated_dependencies.reject(&:informational_only?)
          updater = file_updater_for(deps_to_update)
          updater.updated_dependency_files
        end

        def create_pull_request(dependencies, updated_dependency_files)
          Dependabot.logger.info("Submitting #{dependencies.map(&:name).join(', ')} " \
                                 "pull request for creation")

          dependency_change = Dependabot::DependencyChange.new(
            job: job,
            dependencies: dependencies,
            updated_dependency_files: updated_dependency_files
          )

          service.create_pull_request(dependency_change, dependency_snapshot.base_commit_sha)

          created_pull_requests << dependencies.map do |dep|
            {
              "dependency-name" => dep.name,
              "dependency-version" => dep.version,
              "dependency-removed" => dep.removed? ? true : nil
            }.compact
          end
        end
      end
    end
  end
end
