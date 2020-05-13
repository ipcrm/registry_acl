# frozen_string_literal: true

require 'spec_helper_acceptance'

describe 'registry_acl' do
  tests = {
    'default permissions' => <<~END,
      reg_acl { 'HKLM\\Software':
        target              => 'hklm:software',
        inherit_from_parent => false,
        owner               => 'Administrators',
        permissions         => [
          {
            'IdentityReference' => 'CREATOR OWNER',
            'RegistryRights'    => 'FullControl',
            'AccessControlType' => 'Allow',
            'IsInherited'       => false,
            'InheritanceFlags'  => 'ContainerInherit',
            'PropagationFlags'  => 'InheritOnly',
          },
        ],
      }
    END
  }

  tests.each do |description, test_manifest|
    context description.to_s do
      hosts.each do |host|
        it "applies manifest on #{host}" do
          # Run twice to test idempotency
          apply_manifest(test_manifest, 'catch_failures' => true)
          apply_manifest(test_manifest, 'catch_changes' => true)
        end
      end
    end
  end
end
